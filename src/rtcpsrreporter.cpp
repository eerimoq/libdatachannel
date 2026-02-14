/**
 * Copyright (c) 2020 Filip Klembara (in2core)
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#if RTC_ENABLE_MEDIA

#include "rtcpsrreporter.hpp"

#include <cassert>
#include <chrono>
#include <cmath>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

using namespace std::chrono_literals;

namespace {

// TODO: move to utils
uint64_t ntp_time() {
	const auto now = std::chrono::system_clock::now();
	const double secs = std::chrono::duration<double>(now.time_since_epoch()).count();
	// Assume the epoch is 01/01/1970 and adds the number of seconds between 1900 and 1970
	return uint64_t(std::floor((secs + 2208988800.) * double(uint64_t(1) << 32)));
}

} // namespace

namespace rtc {

RtcpSrReporter::RtcpSrReporter(shared_ptr<RtpPacketizationConfig> rtpConfig) : rtpConfig(rtpConfig) {}

RtcpSrReporter::~RtcpSrReporter() {}

void RtcpSrReporter::setNeedsToReport() {
	// Dummy
}

uint32_t RtcpSrReporter::lastReportedTimestamp() const { return mLastReportedTimestamp; }

optional<std::chrono::milliseconds> RtcpSrReporter::rtt() const {
	auto value = mRtt.load();
	if (value >= 0)
		return std::chrono::milliseconds(value);
	else
		return nullopt;
}

void RtcpSrReporter::incoming(message_vector &messages,
                               [[maybe_unused]] const message_callback &send) {
	for (const auto &message : messages) {
		if (message->type != Message::Control)
			continue;

		size_t offset = 0;
		while (offset + sizeof(RtcpHeader) <= message->size()) {
			auto header = reinterpret_cast<const RtcpHeader *>(message->data() + offset);
			uint8_t payloadType = header->payloadType();
			size_t length = header->lengthInBytes();

			if (length == 0 || offset + length > message->size())
				break;

			// Process Receiver Reports (PT=201)
			if (payloadType == 201 && length >= sizeof(RtcpRr)) {
				printf("xxx got RR\n");
				auto rr = reinterpret_cast<const RtcpRr *>(message->data() + offset);
				int reportCount = header->reportCount();
				for (int i = 0; i < reportCount; ++i) {
					if (offset + sizeof(RtcpHeader) + sizeof(SSRC) +
					        (i + 1) * sizeof(RtcpReportBlock) >
					    message->size())
						break;
					auto block = rr->getReportBlock(i);
					if (block->getSSRC() != rtpConfig->ssrc)
						continue;

					uint32_t lastSR = ntohl(block->_lastReport);
					uint32_t dlsr = block->delaySinceSR();
					if (lastSR == 0)
						continue;

					// Compute compact NTP (middle 32 bits of 64-bit NTP timestamp)
					uint32_t nowCompact = uint32_t(ntp_time() >> 16);

					// Sanity check: if the result would underflow, skip
					if (nowCompact <= lastSR || nowCompact - lastSR <= dlsr)
						continue;

					uint32_t rttCompact = nowCompact - lastSR - dlsr;

					// Convert from 1/65536 seconds to milliseconds
					auto rttMs = int64_t(
					    (double(rttCompact) / 65536.0) * 1000.0);
					mRtt.store(rttMs);
				}
			}

			offset += length;
		}
	}
}

void RtcpSrReporter::outgoing(message_vector &messages, const message_callback &send) {
	if (messages.empty())
		return;

	uint32_t timestamp = 0;
	for (const auto &message : messages) {
		if (message->type == Message::Control)
			continue;

		if (message->size() < sizeof(RtpHeader))
			continue;

		auto header = reinterpret_cast<RtpHeader *>(message->data());
		if(header->ssrc() != rtpConfig->ssrc)
			continue;

		timestamp = header->timestamp();

		addToReport(header, message->size());
	}

	auto now = std::chrono::steady_clock::now();
	if (now >= mLastReportTime + 1s) {
		printf("xxx sending SR\n");
		send(getSenderReport(timestamp));
		mLastReportedTimestamp = timestamp;
		mLastReportTime = now;
	}
}

void RtcpSrReporter::addToReport(RtpHeader *header, size_t size) {
	mPacketCount += 1;
	assert(!header->padding());
	mPayloadOctets += uint32_t(size - header->getSize());
}

message_ptr RtcpSrReporter::getSenderReport(uint32_t timestamp) {
	auto srSize = RtcpSr::Size(0);
	auto msg = make_message(srSize + RtcpSdes::Size({{uint8_t(rtpConfig->cname.size())}}),
	                        Message::Control);
	auto sr = reinterpret_cast<RtcpSr *>(msg->data());
	sr->setNtpTimestamp(ntp_time());
	sr->setRtpTimestamp(timestamp);
	sr->setPacketCount(mPacketCount);
	sr->setOctetCount(mPayloadOctets);
	sr->preparePacket(rtpConfig->ssrc, 0);

	auto sdes = reinterpret_cast<RtcpSdes *>(msg->data() + srSize);
	auto chunk = sdes->getChunk(0);
	chunk->setSSRC(rtpConfig->ssrc);
	auto item = chunk->getItem(0);
	item->type = 1;
	item->setText(rtpConfig->cname);
	sdes->preparePacket(1);

	return msg;
}

} // namespace rtc

#endif /* RTC_ENABLE_MEDIA */
