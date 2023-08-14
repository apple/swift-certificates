//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
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
        let expected = Date(timeIntervalSince1970: 1_656_677_755)
        XCTAssertEqual(expected, Date(.utcTime(utctime)))
    }

    func testConvertGeneralizedTimeToDate() throws {
        // 2022-07-01 12:15:55 corresponds to 1656677755 seconds from 1970.
        let generalizedTime = try GeneralizedTime(
            year: 2022,
            month: 07,
            day: 01,
            hours: 12,
            minutes: 15,
            seconds: 55,
            fractionalSeconds: 0.0
        )
        let expected = Date(timeIntervalSince1970: 1_656_677_755)
        XCTAssertEqual(expected, Date(.generalTime(generalizedTime)))
    }

    func testConvertUTCTimeAsTimeToDate() throws {
        // 2022-07-01 12:15:55 corresponds to 1656677755 seconds from 1970.
        let utctime = try UTCTime(year: 2022, month: 07, day: 01, hours: 12, minutes: 15, seconds: 55)
        let time = Time.utcTime(utctime)
        let expected = Date(timeIntervalSince1970: 1_656_677_755)
        XCTAssertEqual(expected, Date(time))
    }

    func testConvertGeneralizedTimeAsTimeToDate() throws {
        // 2022-07-01 12:15:55 corresponds to 1656677755 seconds from 1970.
        let generalizedTime = try GeneralizedTime(
            year: 2022,
            month: 07,
            day: 01,
            hours: 12,
            minutes: 15,
            seconds: 55,
            fractionalSeconds: 0.0
        )
        let time = Time.generalTime(generalizedTime)
        let expected = Date(timeIntervalSince1970: 1_656_677_755)
        XCTAssertEqual(expected, Date(time))
    }

    func testSpecificInputsForGMTime() throws {
        // These numbers are determined experimentally on macOS.
        let smallestUsableTimeT = Int64(-67_768_040_609_740_800)
        let largestUsableTimeT = Int64(67_768_036_191_676_799)
        let epoch = Int64(0)

        let smallestTime = smallestUsableTimeT.utcDateFromTimestamp
        let largestTime = largestUsableTimeT.utcDateFromTimestamp
        let epochTime = epoch.utcDateFromTimestamp

        XCTAssertEqual(smallestTime.year, -2_147_481_748)
        XCTAssertEqual(smallestTime.month, 1)
        XCTAssertEqual(smallestTime.day, 1)
        XCTAssertEqual(smallestTime.hours, 0)
        XCTAssertEqual(smallestTime.minutes, 0)
        XCTAssertEqual(smallestTime.seconds, 0)

        XCTAssertEqual(largestTime.year, 2_147_485_547)
        XCTAssertEqual(largestTime.month, 12)
        XCTAssertEqual(largestTime.day, 31)
        XCTAssertEqual(largestTime.hours, 23)
        XCTAssertEqual(largestTime.minutes, 59)
        XCTAssertEqual(largestTime.seconds, 59)

        XCTAssertEqual(epochTime.year, 1970)
        XCTAssertEqual(epochTime.month, 1)
        XCTAssertEqual(epochTime.day, 1)
        XCTAssertEqual(epochTime.hours, 0)
        XCTAssertEqual(epochTime.minutes, 0)
        XCTAssertEqual(epochTime.seconds, 0)

        // Test we convert back correctly.
        XCTAssertEqual(smallestUsableTimeT, Int64(timestampFromUTCDate: smallestTime))
        XCTAssertEqual(largestUsableTimeT, Int64(timestampFromUTCDate: largestTime))
        XCTAssertEqual(epoch, Int64(timestampFromUTCDate: epochTime))
    }

    func testCompareRandomInputsForGMTime() throws {
        // These numbers are determined experimentally on macOS.
        let smallestUsableTimeT = Int64(-67_768_040_609_740_800)
        let largestUsableTimeT = Int64(67_768_036_191_676_799)

        // If we're constrained by the system library time_t size, let's do that.
        let lowerBound = max(smallestUsableTimeT, Int64(time_t.min))
        let upperBound = min(largestUsableTimeT, Int64(time_t.max))

        for _ in 0..<10_000 {
            let random = Int64.random(in: lowerBound...upperBound)
            let mine = random.utcDateFromTimestamp

            var time = time_t(random)
            var theirs = tm()
            XCTAssertNotNil(gmtime_r(&time, &theirs), "Seed: \(random)")

            XCTAssertEqual(mine.year, Int(theirs.tm_year) + 1900, "Seed: \(random)")
            XCTAssertEqual(mine.month, Int(theirs.tm_mon) + 1, "Seed: \(random)")
            XCTAssertEqual(mine.day, Int(theirs.tm_mday), "Seed: \(random)")
            XCTAssertEqual(mine.hours, Int(theirs.tm_hour), "Seed: \(random)")
            XCTAssertEqual(mine.minutes, Int(theirs.tm_min), "Seed: \(random)")
            XCTAssertEqual(mine.seconds, Int(theirs.tm_sec), "Seed: \(random)")

            let returned = Int64(timestampFromUTCDate: mine)
            XCTAssertEqual(returned, random)
        }
    }

    func testHandleDaysAndLeapYearsProperly() throws {
        // Start from Sat, 01 Jan 1600 00:00:00 and test every day between then and the year 3000.
        // This tests our year-based computations are probably correct.
        var timestamp = Int64(-11_676_096_000)

        for year in 1600..<3000 {
            let isLeapYear = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)

            for month in 1...12 {
                let days: Int

                switch month {
                case 1, 3, 5, 7, 8, 10, 12:
                    days = 31
                case 4, 6, 9, 11:
                    days = 30
                case 2:
                    days = isLeapYear ? 29 : 28
                default:
                    fatalError()
                }

                for day in 1...days {
                    let computed = timestamp.utcDateFromTimestamp

                    XCTAssertEqual(computed.year, year)
                    XCTAssertEqual(computed.month, month)
                    XCTAssertEqual(computed.day, day)
                    XCTAssertEqual(computed.hours, 0)
                    XCTAssertEqual(computed.minutes, 0)
                    XCTAssertEqual(computed.seconds, 0)

                    let reversed = Int64(timestampFromUTCDate: computed)
                    XCTAssertEqual(reversed, timestamp)

                    // The number of seconds in 1 day.
                    timestamp += 24 * 60 * 60
                }
            }
        }
    }

    func testWeHandleHoursMinutesAndSecondsProperly() throws {
        var timestamp = Int64(0)

        for hours in 0..<24 {
            for minutes in 0..<60 {
                for seconds in 0..<60 {
                    let computed = timestamp.utcDateFromTimestamp

                    XCTAssertEqual(computed.year, 1970)
                    XCTAssertEqual(computed.month, 1)
                    XCTAssertEqual(computed.day, 1)
                    XCTAssertEqual(computed.hours, hours)
                    XCTAssertEqual(computed.minutes, minutes)
                    XCTAssertEqual(computed.seconds, seconds)

                    let reversed = Int64(timestampFromUTCDate: computed)
                    XCTAssertEqual(reversed, timestamp)

                    // Add 1 second and keep going.
                    timestamp += 1
                }
            }
        }
    }
}
