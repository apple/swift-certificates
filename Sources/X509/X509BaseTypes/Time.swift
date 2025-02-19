//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022-2023 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import SwiftASN1

// Time ::= CHOICE {
// utcTime        UTCTime,
// generalTime    GeneralizedTime }
@usableFromInline
enum Time: DERParseable, DERSerializable, Hashable, Sendable {
    case utcTime(UTCTime)
    case generalTime(GeneralizedTime)

    @inlinable
    init(derEncoded rootNode: ASN1Node) throws {
        switch rootNode.identifier {
        case GeneralizedTime.defaultIdentifier:
            self = .generalTime(try GeneralizedTime(derEncoded: rootNode))
        case UTCTime.defaultIdentifier:
            self = .utcTime(try UTCTime(derEncoded: rootNode))
        default:
            throw ASN1Error.unexpectedFieldType(rootNode.identifier)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer) throws {
        switch self {
        case .utcTime(let utcTime):
            try coder.serialize(utcTime)
        case .generalTime(let generalizedTime):
            try coder.serialize(generalizedTime)
        }
    }

    @inlinable
    static func makeTime(from date: Date) throws -> Time {
        let components = date.utcDate

        // The rule is if the year is outside the range 1950-2049 inclusive, we should encode
        // it as a generalized time. Otherwise, use a UTCTime.
        guard ((1950)..<(2050)).contains(components.year) else {
            let generalizedTime = try GeneralizedTime(components)
            return .generalTime(generalizedTime)
        }
        let utcTime = try UTCTime(components)
        return .utcTime(utcTime)
    }
}

extension Date {
    @inlinable
    init(fromUTCDate date: (year: Int, month: Int, day: Int, hours: Int, minutes: Int, seconds: Int)) {
        let timestamp = Int64(timestampFromUTCDate: date)
        self = .init(timeIntervalSince1970: TimeInterval(timestamp))
    }

    @inlinable
    var utcDate: (year: Int, month: Int, day: Int, hours: Int, minutes: Int, seconds: Int) {
        let timestamp = Int64(self.timeIntervalSince1970.rounded())
        return timestamp.utcDateFromTimestamp
    }

    @inlinable
    init(_ time: Time) {
        switch time {
        case .generalTime(let generalizedTime):
            self = .init(generalizedTime)
        case .utcTime(let utcTime):
            self = .init(utcTime)
        }
    }

    @inlinable
    init(_ time: GeneralizedTime) {
        self = Date(
            fromUTCDate: (
                year: time.year, month: time.month, day: time.day, hours: time.hours, minutes: time.minutes,
                seconds: time.seconds
            )
        )
    }

    @inlinable
    init(_ time: UTCTime) {
        self = Date(
            fromUTCDate: (
                year: time.year, month: time.month, day: time.day, hours: time.hours, minutes: time.minutes,
                seconds: time.seconds
            )
        )
    }
}

extension GeneralizedTime {
    @inlinable
    init(_ time: Time) {
        switch time {
        case .generalTime(let t):
            self = t
        case .utcTime(let t):
            // This can never throw, all valid UTCTimes are valid GeneralizedTimes
            self = try! GeneralizedTime(
                year: t.year,
                month: t.month,
                day: t.day,
                hours: t.hours,
                minutes: t.minutes,
                seconds: t.seconds,
                fractionalSeconds: 0
            )
        }
    }

    @inlinable
    init(_ components: (year: Int, month: Int, day: Int, hours: Int, minutes: Int, seconds: Int)) throws {
        try self.init(
            year: components.year,
            month: components.month,
            day: components.day,
            hours: components.hours,
            minutes: components.minutes,
            seconds: components.seconds,
            fractionalSeconds: 0.0
        )
    }

    @inlinable
    init(_ date: Date) {
        // This cannot throw: any valid Date can be represented.
        try! self.init(date.utcDate)
    }
}

extension UTCTime {
    @inlinable
    init(_ components: (year: Int, month: Int, day: Int, hours: Int, minutes: Int, seconds: Int)) throws {
        try self.init(
            year: components.year,
            month: components.month,
            day: components.day,
            hours: components.hours,
            minutes: components.minutes,
            seconds: components.seconds
        )
    }
}
