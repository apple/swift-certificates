import X509
import SwiftASN1
import OSLog

@main
@available(macOS 13, *)
struct ParseWebPKIRoots {
    static func main() throws {
        let derEncodedCAs = try WebPKI.all.map { try PEMDocument(pemString: $0).derBytes }
        
        let signposter = OSSignposter()
        
        let signpostID = signposter.makeSignpostID()
        
        let state = signposter.beginInterval("Parse Certificate", id: signpostID)
                
        var totalExtensionCount = 0
        for derEncodedCA in derEncodedCAs {
            totalExtensionCount += try Certificate(derEncoded: derEncodedCA).extensions.count
        }
        signposter.endInterval("processRequest", state)
        print(totalExtensionCount)
    }
}
