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

// This file contains code derived from the musl implementation at
// https://git.musl-libc.org/cgit/musl/tree/src/time/__secs_to_tm.c and
// https://git.musl-libc.org/cgit/musl/tree/src/time/__tm_to_secs.c.
//
// These implementations have been translated into Swift appropriately for this
// use-case.
//
// The copyright for the original implementation is:
//
//----------------------------------------------------------------------
// Copyright © 2005-2020 Rich Felker, et al.
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//----------------------------------------------------------------------

extension Int64 {
    // 2000-03-01 (mod 400 year, immediately after feb29
    @inlinable
    static var leapoch: Int64 {
        .secondsFromEpochToYear2000 + .secondsPerDay * (31 + 29)
    }

    @inlinable
    static var secondsFromEpochToYear2000: Int64 {
        946_684_800
    }

    @inlinable
    static var daysPer400Years: Int64 {
        365 * 400 + 97
    }

    @inlinable
    static var daysPer100Years: Int64 {
        365 * 100 + 24
    }

    @inlinable
    static var daysPer4Years: Int64 {
        365 * 4 + 1
    }

    @inlinable
    static var secondsPerDay: Int64 {
        24 * 60 * 60
    }

    @inlinable
    static var secondsPerYear: Int64 {
        .secondsPerDay * .daysPerYear
    }

    @inlinable
    static var daysPerYear: Int64 {
        365
    }

    @inlinable
    static func daysInMonth(_ month: Int) -> Int64 {
        // This may seem weird, but these months are indexed from _March_.
        // Thus, month 0 is March, month 11 is February.
        switch month {
        case 0, 2, 4, 5, 7, 9, 10:
            return 31
        case 1, 3, 6, 8:
            return 30
        case 11:
            return 29
        default:
            fatalError()
        }
    }

    @inlinable
    var utcDateFromTimestamp: (year: Int, month: Int, day: Int, hours: Int, minutes: Int, seconds: Int) {
        let secs = self - .leapoch
        var (days, remsecs) = secs.quotientAndRemainder(dividingBy: 86400)

        // Tolerate negative values
        if remsecs < 0 {
            // Unchecked is safe here: we know remsecs is negative, and we know
            // days cannot be Int64.min
            remsecs &+= .secondsPerDay
            days &-= 1
        }

        var (qcCycles, remdays) = days.quotientAndRemainder(dividingBy: .daysPer400Years)
        if remdays < 0 {
            // Same justification here for unchecked arithmetic
            remdays &+= .daysPer400Years
            qcCycles &-= 1
        }

        // Unchecked arithmetic here is safe: the subtraction is all known values (4 - 1),
        // and the multiplication cannot exceed the original value of remdays.
        var cCycles = remdays / .daysPer100Years
        if cCycles == 4 { cCycles &-= 1 }
        remdays &-= cCycles &* .daysPer100Years

        // Unchecked arithmetic here is safe: the subtraction is all known values (25 - 1),
        // and the multiplication cannot exceed the original value of remdays.
        var qCycles = remdays / .daysPer4Years
        if qCycles == 25 { qCycles &-= 1 }
        remdays &-= qCycles &* .daysPer4Years

        // Unchecked arithmetic here is safe: the subtraction is all known values (4 - 1),
        // and the multiplication cannot exceed the original value of remdays.
        var remyears = remdays / .daysPerYear
        if remyears == 4 { remyears &-= 1 }
        remdays &-= remyears &* .daysPerYear

        // Unchecked multiplication here is safe: each of these has earlier been multiplied by
        // a much larger number and we didn't need checked math then, so we don't need it now.
        var years = remyears + (4 &* qCycles) + (100 &* cCycles) + (400 &* qcCycles)

        var months = 0
        while Int64.daysInMonth(months) <= remdays {
            remdays -= Int64.daysInMonth(months)

            // Unchecked because daysInMonth will crash if given a value greater than 12, so this
            // cannot exceed 12.
            months &+= 1
        }

        // Now we normalise the months count back to starting in January.
        // Safe to do unchecked subtraction here because for all numbers 10 or
        // larger we can subtract by 12.
        if months >= 10 {
            months &-= 12
            years += 1
        }

        // Normalise out the values.
        //
        // Safe to do unchecked math on the months as we just checked its value above.
        // Same for remdays, the loop only terminates if the number is smaller than at most 31.
        //
        // Note that, unlike struct tm, we return ordinal month numbers as well as days (i.e. 1 to 12).
        // This fits us better when working with GeneralizedTime and friends.
        return (
            year: Int(years + 2000),
            month: Int(months &+ 3),
            day: Int(remdays &+ 1),
            hours: Int(remsecs / 3600),
            minutes: Int(remsecs / 60 % 60),
            seconds: Int(remsecs % 60)
        )
    }

    @inlinable
    init(timestampFromUTCDate date: (year: Int, month: Int, day: Int, hours: Int, minutes: Int, seconds: Int)) {
        assert((1...12).contains(date.month))
        assert((0...31).contains(date.day))
        assert((0..<24).contains(date.hours))
        assert((0..<60).contains(date.minutes))
        assert((0..<61).contains(date.seconds))

        // The algorithm as written expects a tm year, which is years away from 1900, and a tm_month, which is 0-11 instead of 1-12.
        // We don't want that nonsense. Undo it here.
        var (seconds, isLeap) = Self.yearToSeconds(Int64(date.year) - 1900)
        seconds += Self.monthToSeconds(Int64(date.month) - 1, isLeap: isLeap)

        // Note that we tolerate invalid day/hour/minute/seconds. That's ok in this context,
        // we validate elsewhere. However, we don't do unchecked math for that reason.
        seconds += .secondsPerDay * (Int64(date.day) - 1)
        seconds += 3600 * Int64(date.hours)
        seconds += 60 * Int64(date.minutes)
        seconds += Int64(date.seconds)

        self = seconds
    }

    @inlinable
    static func yearToSeconds(_ year: Int64) -> (seconds: Int64, isLeap: Bool) {
        var (cycles, rem) = (year - 100).quotientAndRemainder(dividingBy: 400)
        if rem < 0 {
            // Unchecked is safe here: we know rem is negative, and we know
            // cycles cannot be Int64.min
            cycles &-= 1
            rem &+= 400
        }

        let centuries: Int64
        let isLeap: Bool
        var leaps: Int64

        if rem == 0 {
            isLeap = true
            centuries = 0
            leaps = 0
        } else {
            switch rem {
            case 300...:
                centuries = 3
                rem &-= 300
            case 200...:
                centuries = 2
                rem &-= 200
            case 100...:
                centuries = 1
                rem &-= 100
            default:
                assert(rem > 0)
                centuries = 0
            }

            if rem == 0 {
                isLeap = false
                leaps = 0
            } else {
                (leaps, rem) = rem.quotientAndRemainder(dividingBy: 4)
                isLeap = (rem == 0)
            }
        }

        leaps += (97 * cycles) + (24 * centuries) - (isLeap ? 1 : 0)
        return (
            seconds: ((year - 100) * .secondsPerYear) + (leaps * .secondsPerDay) + .secondsFromEpochToYear2000
                + .secondsPerDay, isLeap: isLeap
        )
    }

    @inlinable
    static func monthToSeconds(_ month: Int64, isLeap: Bool) -> Int64 {
        var secondsThroughMonth: Int64

        // musl tolerates out-of-band months: we don't.
        switch month {
        case 0:
            secondsThroughMonth = 0
        case 1:
            secondsThroughMonth = 31 * .secondsPerDay
        case 2:
            secondsThroughMonth = 59 * .secondsPerDay
        case 3:
            secondsThroughMonth = 90 * .secondsPerDay
        case 4:
            secondsThroughMonth = 120 * .secondsPerDay
        case 5:
            secondsThroughMonth = 151 * .secondsPerDay
        case 6:
            secondsThroughMonth = 181 * .secondsPerDay
        case 7:
            secondsThroughMonth = 212 * .secondsPerDay
        case 8:
            secondsThroughMonth = 243 * .secondsPerDay
        case 9:
            secondsThroughMonth = 273 * .secondsPerDay
        case 10:
            secondsThroughMonth = 304 * .secondsPerDay
        case 11:
            secondsThroughMonth = 334 * .secondsPerDay
        default:
            fatalError("Invalid month: \(month)")
        }

        if isLeap && month >= 2 {
            // Unchecked is safe here, none of the above values will overflow when this is added to them.
            secondsThroughMonth &+= .secondsPerDay
        }

        return secondsThroughMonth
    }
}
