//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificate open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificate project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCertificate project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest
import SwiftASN1
@testable import X509

final class TimeTests: XCTestCase {
    func testConvertUTCTimeToDate() throws {
        // 2022-07-01 12:15:55 corresponds to 1656677755 seconds from 1970.
        let utctime = try UTCTime(year: 2022, month: 07, day: 01, hours: 12, minutes: 15, seconds: 55)
        let expected = Date(timeIntervalSince1970: 1656677755)
        XCTAssertEqual(expected, Date(utctime))
    }

    func testConvertGeneralizedTimeToDate() throws {
        // 2022-07-01 12:15:55 corresponds to 1656677755 seconds from 1970.
        let generalizedTime = try GeneralizedTime(year: 2022, month: 07, day: 01, hours: 12, minutes: 15, seconds: 55, fractionalSeconds: 0.0)
        let expected = Date(timeIntervalSince1970: 1656677755)
        XCTAssertEqual(expected, Date(generalizedTime))
    }

    func testConvertUTCTimeAsTimeToDate() throws {
        // 2022-07-01 12:15:55 corresponds to 1656677755 seconds from 1970.
        let utctime = try UTCTime(year: 2022, month: 07, day: 01, hours: 12, minutes: 15, seconds: 55)
        let time = Time.utcTime(utctime)
        let expected = Date(timeIntervalSince1970: 1656677755)
        XCTAssertEqual(expected, Date(time))
    }

    func testConvertGeneralizedTimeAsTimeToDate() throws {
        // 2022-07-01 12:15:55 corresponds to 1656677755 seconds from 1970.
        let generalizedTime = try GeneralizedTime(year: 2022, month: 07, day: 01, hours: 12, minutes: 15, seconds: 55, fractionalSeconds: 0.0)
        let time = Time.generalTime(generalizedTime)
        let expected = Date(timeIntervalSince1970: 1656677755)
        XCTAssertEqual(expected, Date(time))
    }
}
