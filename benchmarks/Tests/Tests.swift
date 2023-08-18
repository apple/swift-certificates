import Sources
import XCTest

final class TestRunner: XCTestCase {
    override func setUpWithError() throws {
        #if DEBUG
        throw XCTSkip("performance tests only run in release mode")
        #endif
    }
    func testVerifier() async {
        for _ in 0..<100 {
            await verifier()
        }
    }
    
    func testPraseWebPKIRoots() {
        let runParseWebPKIRoots = parseWebPKIRoots()
        for _ in 0..<1000 {
            runParseWebPKIRoots()
        }
    }
    
    func testTinyArrayNonAllocationFunctions() {
        for _ in 0..<1000 {
            tinyArrayNonAllocationFunctions()
        }
    }
    
    func testTinyArrayAppend() {
        for _ in 0..<1000 {
            tinyArrayAppend()
        }
    }
}
