// Keymaster, access Keychain secrets guarded by TouchID or password
import Foundation
import LocalAuthentication
import Security


func setPassword(key: String, password: String) -> Bool {
  guard let data = password.data(using: .utf8) else { return false }

  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecValueData as String: data
  ]

  SecItemDelete(query as CFDictionary)
  let status = SecItemAdd(query as CFDictionary, nil)
  return status == errSecSuccess
}

func deletePassword(key: String) -> Bool {
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key
  ]
  let status = SecItemDelete(query as CFDictionary)
  return status == errSecSuccess
}

func getPassword(key: String) -> String? {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecMatchLimit as String: kSecMatchLimitOne,
    kSecReturnData as String: kCFBooleanTrue as Any
  ]
  var item: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &item)

  guard status == errSecSuccess,
    let passwordData = item as? Data,
    let password = String(data: passwordData, encoding: .utf8)
  else { return nil }

  return password
}

func authenticate(reason: String, completion: @escaping (Bool) -> Void) {
  let context = LAContext()
  context.touchIDAuthenticationAllowableReuseDuration = 0

  var error: NSError?

  if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                           localizedReason: reason) { success, evalError in
      if success {
        completion(true)
      } else {
        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) {
          context.evaluatePolicy(.deviceOwnerAuthentication,
                                 localizedReason: reason) { success2, _ in
            completion(success2)
          }
        } else {
          fputs("Fallback authentication not available: \(evalError?.localizedDescription ?? "unknown")\n", stderr)
          completion(false)
        }
      }
    }
    return
  }

  if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
    context.evaluatePolicy(.deviceOwnerAuthentication,
                           localizedReason: reason) { success, evalError in
      if !success {
        fputs("Authentication failed: \(evalError?.localizedDescription ?? "unknown")\n", stderr)
      }
      completion(success)
    }
  } else {
    fputs("No authentication method available: \(error?.localizedDescription ?? "unknown")\n", stderr)
    completion(false)
  }
}

func usage() {
  print("keymaster [get|set|delete] [key] [secret]")
}

func main() {
  let inputArgs: [String] = Array(CommandLine.arguments.dropFirst())
  if (inputArgs.count < 2 || inputArgs.count > 3) {
    usage()
    exit(EXIT_FAILURE) 
  }
  let action = inputArgs[0]
  let key = inputArgs[1]
  var secret = ""
  if (action == "set" && inputArgs.count == 3) {
    secret = inputArgs[2]
  }

  let reason: String
  switch action {
  case "set":    reason = "Set the secret for \(key)"
  case "get":    reason = "Access the secret for \(key)"
  case "delete": reason = "Delete the secret for \(key)"
  default:
    usage()
    exit(EXIT_FAILURE)
  }

  authenticate(reason: reason) { authed in
    guard authed else {
      fputs("Authentication failed or was cancelled.\n", stderr)
      exit(EXIT_FAILURE)
    }

    switch action {
    case "set":
      guard setPassword(key: key, password: secret) else {
        fputs("Error setting password\n", stderr)
        exit(EXIT_FAILURE)
      }
      print("Key \(key) has been successfully set in the keychain")
      exit(EXIT_SUCCESS)

    case "get":
      guard let password = getPassword(key: key) else {
        fputs("Error getting password\n", stderr)
        exit(EXIT_FAILURE)
      }
      print(password)
      exit(EXIT_SUCCESS)

    case "delete":
      guard deletePassword(key: key) else {
        fputs("Error deleting password\n", stderr)
        exit(EXIT_FAILURE)
      }
      print("Key \(key) has been successfully deleted from the keychain")
      exit(EXIT_SUCCESS)
    default:
      usage()
      exit(EXIT_FAILURE)
    }
  }
  dispatchMain()
}

main()
