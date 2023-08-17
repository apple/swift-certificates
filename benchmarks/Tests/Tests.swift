import Sources
import XCTest

final class TestRunner: XCTestCase {
    func testVerifier() async {
        for _ in 0..<100 {
            await verifier()
        }
    }
    
    func testPraseWebPKIRoots() {
        let runParseWebPKIRoots = parseWebPKIRoots()
        for _ in 0..<10000 {
            runParseWebPKIRoots()
        }
    }
    
    func testTinyArrayNonAllocationFunctions() {
        
        tinyArrayNonAllocationFunctions()
        
    }
    
    func testTinyArrayAppend() {
        
        tinyArrayAppend()
        
    }
}
