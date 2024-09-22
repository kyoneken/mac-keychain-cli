import Foundation
import Security

class KeychainManager {
    private let serviceName: String
    private let accessGroup: String?
    
    init(serviceName: String, accessGroup: String? = nil) {
        self.serviceName = serviceName
        self.accessGroup = accessGroup
    }
    
    func addItem(account: String, password: String) -> OSStatus {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecValueData as String: password.data(using: .utf8)!
        ]
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        SecItemDelete(query as CFDictionary)
        return SecItemAdd(query as CFDictionary, nil)
    }
    
    func getPassword(for account: String) -> String? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true
        ]
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            print("Error finding password: \(status)")
            return nil
        }
        
        guard let passwordData = result as? Data,
              let password = String(data: passwordData, encoding: .utf8) else {
            return nil
        }
        
        return password
    }
}

func copyToClipboard(_ string: String) {
    let task = Process()
    task.launchPath = "/usr/bin/pbcopy"
    task.arguments = []
    
    let pipe = Pipe()
    task.standardInput = pipe
    task.launch()
    
    let data = string.data(using: .utf8)!
    pipe.fileHandleForWriting.write(data)
    pipe.fileHandleForWriting.closeFile()
    
    task.waitUntilExit()
}

func interactiveMode() {
    let manager = KeychainManager(serviceName: "com.github.kyoneken.mac-keychain-cli")
    
    print("Welcome to the Custom Keychain CLI Tool")
    
    while true {
        print("\nChoose an option:")
        print("1. Add item")
        print("2. Get password")
        print("3. Exit")
        
        guard let choice = readLine(), let option = Int(choice) else {
            print("Invalid input. Please try again.")
            continue
        }
        
        switch option {
        case 1:
            print("Enter account name:")
            guard let account = readLine(), !account.isEmpty else {
                print("Invalid account name.")
                continue
            }
            print("Enter password:")
            guard let password = readLine(), !password.isEmpty else {
                print("Invalid password.")
                continue
            }
            let status = manager.addItem(account: account, password: password)
            print("Add item status: \(status)")
            
        case 2:
            print("Enter account name:")
            guard let account = readLine(), !account.isEmpty else {
                print("Invalid account name.")
                continue
            }
            if let password = manager.getPassword(for: account) {
                copyToClipboard(password)
                print("Password copied to clipboard.")
            } else {
                print("Password not found.")
            }
            
        case 3:
            print("Goodbye!")
            return
            
        default:
            print("Invalid option. Please try again.")
        }
    }
}

interactiveMode()