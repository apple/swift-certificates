import Foundation

@_spi(IntegrationTests) public enum WebPKI {
    public static var roots: [URL] {
        Bundle.module.urls(forResourcesWithExtension: "crt", subdirectory: "roots")!
    }
}
