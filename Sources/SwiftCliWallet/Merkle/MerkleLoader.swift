import Foundation

func loadMerkleRoot(from path: String) -> MerkleRoot? {
    let url = URL(fileURLWithPath: path)
    guard let data = try? Data(contentsOf: url) else { return nil }
    let decoder = JSONDecoder()
    return try? decoder.decode(MerkleRoot.self, from: data)
}
