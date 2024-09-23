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

    func getItemList() -> [String] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: false
        ]
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess, let items = result as? [[String: Any]] else {
            print("Error retrieving item list: \(status)")
            return []
        }
        
        var itemList: [String] = []
        for item in items {
            if let account = item[kSecAttrAccount as String] as? String {
                itemList.append(account)
            }
        }
        
        return itemList
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

    func exportItems(to filePath: String) -> Bool {
        let itemList = getItemList()
        
        guard !itemList.isEmpty else {
            print("No items to export.")
            return false
        }
        
        var exportData: [[String: String]] = []
        
        for account in itemList {
            if let password = getPassword(for: account) {
                exportData.append(["account": account, "password": password])
            }
        }
        
        do {
            let jsonData = try JSONSerialization.data(withJSONObject: exportData, options: .prettyPrinted)
            let fileURL = URL(fileURLWithPath: filePath)
            try jsonData.write(to: fileURL)
            print("Items successfully exported to \(filePath)")
            return true
        } catch {
            print("Error exporting items: \(error)")
            return false
        }
    }
    
    func importItems(from filePath: String) -> Bool {
        let fileURL = URL(fileURLWithPath: filePath)
        
        do {
            let data = try Data(contentsOf: fileURL)
            guard let itemList = try JSONSerialization.jsonObject(with: data, options: []) as? [[String: String]] else {
                print("Invalid JSON format")
                return false
            }
            
            for item in itemList {
                if let account = item["account"], let password = item["password"] {
                    let status = addItem(account: account, password: password)
                    print("Imported \(account): Status \(status)")
                }
            }
            return true
        } catch {
            print("Error importing items: \(error)")
            return false
        }
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
        print("2. Get password from item list")
        print("3. Export items")
        print("4. Import items")
        print("5. Exit")
        
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
            let itemList = manager.getItemList()
            if itemList.isEmpty {
                print("No items found.")
                continue
            }
            
            print("Select an account from the list:")
            for (index, item) in itemList.enumerated() {
                print("\(index + 1). \(item)")
            }
            
            guard let itemChoice = readLine(), let itemIndex = Int(itemChoice), itemIndex > 0, itemIndex <= itemList.count else {
                print("Invalid selection.")
                continue
            }
            
            let selectedAccount = itemList[itemIndex - 1]
            if let password = manager.getPassword(for: selectedAccount) {
                copyToClipboard(password)
                print("Password for '\(selectedAccount)' copied to clipboard.")
            } else {
                print("Password not found.")
            }
            
        case 3:
            print("Enter file path to export items:")
            guard let filePath = readLine(), !filePath.isEmpty else {
                print("Invalid file path.")
                continue
            }
            let success = manager.exportItems(to: filePath)
            print(success ? "Export successful." : "Export failed.")
            
        case 4:
            print("Enter file path to import items:")
            guard let filePath = readLine(), !filePath.isEmpty else {
                print("Invalid file path.")
                continue
            }
            let success = manager.importItems(from: filePath)
            print(success ? "Import successful." : "Import failed.")
            
        case 5:
            print("Goodbye!")
            return
            
        default:
            print("Invalid option. Please try again.")
        }
    }
}

interactiveMode()