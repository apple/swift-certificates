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

/// Provides a result-builder style DSL for constructing ``Certificate/Extensions-swift.struct`` values.
///
/// This DSL allows us to construct extensions straightforwardly, using their high-level representation instead of
/// the erased representation provided by ``Certificate/Extension``. For example, a simple set of
/// extensions can be produced like this:
///
/// ```swift
/// let extensions = Certificate.Extensions {
///     Critical(
///         Certificate.Extensions.KeyUsage(digitalSignature: true, keyCertSign: true, cRLSign: true)
///     )
///
///     Certificate.Extensions.ExtendedKeyUsage([.serverAuth, .clientAuth])
///
///     Critical(
///         Certificate.Extensions.BasicConstraints.isCertificateAuthority(maxPathLength: 0)
///     )
///
///     Certificate.Extensions.AuthorityInformationAccess([.init(method: .ocspServer, location: .uniformResourceIdentifier("http://ocsp.digicert.com"))])
/// }
/// ```
///
/// Users can extend this syntax for their own extensions by conforming their semantic type to ``CertificateExtensionConvertible``.
/// This is the only requirement for adding new extensions to this builder syntax.
///
/// Users are also able to mark specific extensions as critical by using the ``Critical`` helper type.
@resultBuilder
public struct ExtensionsBuilder {
    @inlinable
    public static func buildExpression<Extension: CertificateExtensionConvertible>(_ expression: Extension) -> Certificate.Extensions {
        // TODO: we really need a way to avoid having this be try!.
        try! Certificate.Extensions([expression.makeCertificateExtension()])
    }

    @inlinable
    public static func buildBlock(_ components: Certificate.Extensions...) -> Certificate.Extensions {
        Certificate.Extensions(components.lazy.flatMap { $0 })
    }

    @inlinable
    public static func buildOptional(_ component: Certificate.Extensions?) -> Certificate.Extensions {
        component ?? Certificate.Extensions([])
    }

    @inlinable
    public static func buildEither(first component: Certificate.Extensions) -> Certificate.Extensions {
        component
    }

    @inlinable
    public static func buildEither(second component: Certificate.Extensions) -> Certificate.Extensions {
        component
    }

    @inlinable
    public static func buildArray(_ components: [Certificate.Extensions]) -> Certificate.Extensions {
        Certificate.Extensions(components.lazy.flatMap { $0 })
    }

    @inlinable
    public static func buildLimitedAvailability(_ component: Certificate.Extensions) -> Certificate.Extensions {
        component
    }
}

/// Conforming types are capable of being erased into ``Certificate/Extension`` values.
///
/// Note that for most extension types, the returned ``Certificate/Extension`` should have its
/// ``Certificate/Extension/critical`` value set to `false`. This allows the ``Critical`` helper
/// type to fulfil its function as expected.
public protocol CertificateExtensionConvertible {
    /// Convert the value into a ``Certificate/Extension``.
    func makeCertificateExtension() throws -> Certificate.Extension
}

/// Marks a given ``CertificateExtensionConvertible`` value as critical.
///
/// This type is used only within the ``ExtensionsBuilder`` DSL to mark extensions as critical.
@frozen
public struct Critical<BaseExtension: CertificateExtensionConvertible>: CertificateExtensionConvertible {
    /// The ``CertificateExtensionConvertible`` backing this value.
    public var base: BaseExtension

    /// Wrap a ``CertificateExtensionConvertible`` value and mark it critical.
    @inlinable
    public init(_ base: BaseExtension) {
        self.base = base
    }

    @inlinable
    public func makeCertificateExtension() throws -> Certificate.Extension {
        var ext = try self.base.makeCertificateExtension()
        ext.critical = true
        return ext
    }
}
