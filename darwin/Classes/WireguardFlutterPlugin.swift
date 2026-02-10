#if os(iOS)
import Flutter
import UIKit
#elseif os(macOS)
import FlutterMacOS
import Cocoa
#else
#error("Unsupported platform")
#endif

import NetworkExtension

public class WireguardFlutterPlugin: NSObject, FlutterPlugin {
    private static var utils : VPNUtils! = VPNUtils()

    public static var stage: FlutterEventSink?
    private var initialized : Bool = false
     var wireguardMethodChannel: FlutterMethodChannel?

    public static func register(with registrar: FlutterPluginRegistrar) {

        let instance = WireguardFlutterPlugin()
        instance.onRegister(registrar)
    }

    public func onRegister(_ registrar: FlutterPluginRegistrar){
        #if os(iOS)
        let messenger = registrar.messenger()
        #else
        let messenger = registrar.messenger
        #endif
        let wireguardMethodChannel = FlutterMethodChannel(name: "billion.group.wireguard_flutter/wgcontrol", binaryMessenger: messenger)
        let vpnStageE = FlutterEventChannel(name: "billion.group.wireguard_flutter/wgstage", binaryMessenger: messenger)
        vpnStageE.setStreamHandler(VPNConnectionHandler())
        wireguardMethodChannel.setMethodCallHandler { (call: FlutterMethodCall, result: @escaping FlutterResult) -> Void in
            switch call.method {
            case "stage":
                result(WireguardFlutterPlugin.utils.currentStatus())
            case "initialize":
                let localizedDescription: String? = (call.arguments as? [String: Any])?["localizedDescription"] as? String
                if localizedDescription == nil {
                    result(FlutterError(code: "-3", message: "localizedDescription content empty or null", details: nil))
                    return
                }
                WireguardFlutterPlugin.utils.localizedDescription = localizedDescription
                WireguardFlutterPlugin.utils.loadProviderManager { (err: Error?) in
                    if err == nil {
                        result(WireguardFlutterPlugin.utils.currentStatus())
                    } else {
                        result(FlutterError(code: "-4", message: err.debugDescription, details: err?.localizedDescription))
                    }
                }
                self.initialized = true
            case "stop":
                WireguardFlutterPlugin.utils.isConnecting = false
                WireguardFlutterPlugin.utils.isDisconnecting = true
                self.disconnect(result: result)
            case "start":
                let serverAddress: String? = (call.arguments as? [String: Any])?["serverAddress"] as? String
                let wgQuickConfig: String? = (call.arguments as? [String: Any])?["wgQuickConfig"] as? String
                let providerBundleIdentifier: String? = (call.arguments as? [String: Any])?["providerBundleIdentifier"] as? String
                WireguardFlutterPlugin.utils.isDisconnecting = false
                WireguardFlutterPlugin.utils.isConnecting = true
                self.connect(serverAddress: serverAddress!, wgQuickConfig: wgQuickConfig!, providerBundleIdentifier: providerBundleIdentifier!, result: result)
            case "dispose":
                self.initialized = false
            case "getStats":
                WireguardFlutterPlugin.utils.getStatistics { statsResult in
                  switch statsResult {
                  case .success(let statistics):
                      result(statistics)
                  case .failure(let error):
                      result(FlutterError(code: "-5", message: error.localizedDescription, details: nil))
                  }
              }
            default:
                result(FlutterMethodNotImplemented)
            }
        }
    }

    private func connect(serverAddress: String, wgQuickConfig: String, providerBundleIdentifier:String, result: @escaping FlutterResult) {
        WireguardFlutterPlugin.utils.configureVPN(serverAddress: serverAddress, wgQuickConfig: wgQuickConfig, providerBundleIdentifier: providerBundleIdentifier) { success in
            if !success {
                WireguardFlutterPlugin.utils.isConnecting = false
            }
            result(success)
        }
    }

    private func disconnect(result: @escaping FlutterResult) {
        WireguardFlutterPlugin.utils.stopVPN() { success in
            result(success)
        }
    }

    class VPNConnectionHandler: NSObject, FlutterStreamHandler {
        private var vpnConnection: FlutterEventSink?
        private var vpnConnectionObserver: NSObjectProtocol?
        private var connectedAt: Date?
        private var disconnectVerifyTimer: DispatchWorkItem?

        /// Grace period after connected — spurious disconnected events within this
        /// window are verified against actual tunnel status before forwarding.
        private let postConnectGracePeriod: TimeInterval = 3.0

        func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
            // Remove existing observer if any
            if let observer = vpnConnectionObserver {
                NotificationCenter.default.removeObserver(observer)
            }

            // Assign event sink BEFORE setting up observer to avoid race
            self.vpnConnection = events

            vpnConnectionObserver = NotificationCenter.default.addObserver(
                forName: NSNotification.Name.NEVPNStatusDidChange, object: nil, queue: .main
            ) { [weak self] notification in
                guard let self = self, let connection = self.vpnConnection else {
                    return
                }

                let nevpnconn = notification.object as! NEVPNConnection
                let status = nevpnconn.status
                let stageString = WireguardFlutterPlugin.utils.onVpnStatusChangedString(notification: status)

                // Suppress transient disconnected/invalid during connect
                if WireguardFlutterPlugin.utils.isConnecting {
                    if stageString == "disconnected" || stageString == "invalid" {
                        NSLog("WireGuard: Suppressing transient '\(stageString ?? "nil")' during connect")
                        return
                    }
                    // Clear connecting flag on definitive states
                    if stageString == "connected" || stageString == "denied" || stageString == "no_connection" {
                        WireguardFlutterPlugin.utils.isConnecting = false
                    }
                }

                // Suppress late events during disconnect
                if WireguardFlutterPlugin.utils.isDisconnecting {
                    if stageString == "connected" || stageString == "connecting" {
                        NSLog("WireGuard: Suppressing late '\(stageString ?? "nil")' during disconnect")
                        return
                    }
                    if stageString == "disconnected" {
                        WireguardFlutterPlugin.utils.isDisconnecting = false
                    }
                }

                // Track when we become connected
                if stageString == "connected" {
                    self.connectedAt = Date()
                    self.disconnectVerifyTimer?.cancel()
                    self.disconnectVerifyTimer = nil
                }

                // Post-connect grace: verify disconnected before forwarding
                if stageString == "disconnected", let connectedTime = self.connectedAt {
                    let elapsed = Date().timeIntervalSince(connectedTime)
                    if elapsed < self.postConnectGracePeriod {
                        NSLog("WireGuard: Disconnected %.1fs after connected — verifying actual status", elapsed)
                        self.disconnectVerifyTimer?.cancel()
                        let verifyWork = DispatchWorkItem { [weak self] in
                            guard let self = self, let conn = self.vpnConnection else { return }
                            NETunnelProviderManager.loadAllFromPreferences { managers, _ in
                                DispatchQueue.main.async {
                                    let actualStatus = managers?.first?.connection.status
                                    let actualString = WireguardFlutterPlugin.utils.onVpnStatusChangedString(notification: actualStatus)
                                    if actualString == "connected" {
                                        NSLog("WireGuard: Tunnel still connected — suppressing spurious disconnected")
                                    } else {
                                        NSLog("WireGuard: Tunnel confirmed disconnected — forwarding")
                                        self?.connectedAt = nil
                                        conn(actualString)
                                    }
                                }
                            }
                        }
                        self.disconnectVerifyTimer = verifyWork
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5, execute: verifyWork)
                        return
                    } else {
                        // Beyond grace period — genuine disconnect
                        self.connectedAt = nil
                    }
                }

                connection(stageString)
            }

            // Load current status — but skip if we're mid-connect/disconnect
            if !WireguardFlutterPlugin.utils.isConnecting && !WireguardFlutterPlugin.utils.isDisconnecting {
                NETunnelProviderManager.loadAllFromPreferences { managers, error in
                    DispatchQueue.main.async {
                        events(WireguardFlutterPlugin.utils.onVpnStatusChangedString(notification: managers?.first?.connection.status))
                    }
                }
            }

            return nil
        }

        func onCancel(withArguments arguments: Any?) -> FlutterError? {
            if let observer = vpnConnectionObserver {
                NotificationCenter.default.removeObserver(observer)
            }
            disconnectVerifyTimer?.cancel()
            disconnectVerifyTimer = nil
            vpnConnection = nil

            return nil
        }
    }
}

@available(iOS 15.0, *)
class VPNUtils {
    var providerManager: NETunnelProviderManager!
    var providerBundleIdentifier: String?
    var localizedDescription: String?
    var groupIdentifier: String?
    var serverAddress: String?
    var stage: FlutterEventSink!
    var isConnecting: Bool = false
    var isDisconnecting: Bool = false

    func loadProviderManager(completion: @escaping (_ error: Error?) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { (managers, error) in
            if error == nil {
                self.providerManager = managers?.first ?? NETunnelProviderManager()
                completion(nil)
            } else {
                completion(error)
            }
        }
    }

    func getStatistics(completion: @escaping (Result<String, Error>) -> Void) {
        DispatchQueue.global(qos: .utility).async {
            self.loadProviderManager { error in
                if let error = error {
                    completion(.failure(error))
                    return
                }

                guard let session = self.providerManager.connection as? NETunnelProviderSession else {
                    completion(.failure(NSError(domain: "VPNUtils", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid session"])))
                    return
                }

                do {
                    try session.sendProviderMessage("GET_STATISTICS".data(using: .utf8)!) { response in
                        guard
                            let response = response,
                            let responseString = String(data: response, encoding: .utf8)
                        else {
                            completion(.failure(NSError(domain: "VPNUtils", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to get response"])))
                            return
                        }
                        completion(.success(responseString))
                    }
                } catch {
                    completion(.failure(error))
                }
            }
        }
    }

    func onVpnStatusChanged(notification: NEVPNStatus) {
        switch notification {
        case .connected:
            stage?("connected")
        case .connecting:
            stage?("connecting")
        case .disconnected:
            stage?("disconnected")
        case .disconnecting:
            stage?("disconnecting")
        case .invalid:
            stage?("disconnected")
        case .reasserting:
            stage?("connecting")
        @unknown default:
            stage?("disconnected")
        }
    }

    func onVpnStatusChangedString(notification: NEVPNStatus?) -> String? {
        if notification == nil {
            return "disconnected"
        }
        switch notification! {
        case NEVPNStatus.connected:
            return "connected"
        case NEVPNStatus.connecting:
            return "connecting"
        case NEVPNStatus.disconnected:
            return "disconnected"
        case NEVPNStatus.disconnecting:
            return "disconnecting"
        case NEVPNStatus.invalid:
            return "disconnected"
        case NEVPNStatus.reasserting:
            return "connecting"
        default:
            return "disconnected"
        }
    }

    func currentStatus() -> String? {
        if self.providerManager != nil {
            return onVpnStatusChangedString(notification: self.providerManager.connection.status)
        } else {
            return "disconnected"
        }
    }

    func configureVPN(serverAddress: String?, wgQuickConfig: String?, providerBundleIdentifier: String?, completion: @escaping (Bool) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { tunnelManagersInSettings, error in
            if let error = error {
                NSLog("Error (loadAllFromPreferences): \(error)")
                completion(false)
                return
            }
            let preExistingTunnelManager = tunnelManagersInSettings?.first
            let tunnelManager = preExistingTunnelManager ?? NETunnelProviderManager()

            let protocolConfiguration = NETunnelProviderProtocol()

            protocolConfiguration.providerBundleIdentifier = providerBundleIdentifier!
            protocolConfiguration.serverAddress = serverAddress
            protocolConfiguration.providerConfiguration = ["wgQuickConfig": wgQuickConfig!]

            tunnelManager.protocolConfiguration = protocolConfiguration
            tunnelManager.isEnabled = true

            tunnelManager.saveToPreferences { error in
                if let error = error {
                    NSLog("Error (saveToPreferences): \(error)")
                    completion(false)
                } else {
                    tunnelManager.loadFromPreferences { error in
                        if let error = error {
                            NSLog("Error (loadFromPreferences): \(error)")
                            completion(false)
                        } else {
                            NSLog("Starting the tunnel")
                            if let session = tunnelManager.connection as? NETunnelProviderSession {
                                do {
                                    try session.startTunnel(options: nil)
                                    completion(true)
                                } catch {
                                    NSLog("Error (startTunnel): \(error)")
                                    completion(false)
                                }
                            } else {
                                NSLog("tunnelManager.connection is invalid")
                                completion(false)
                            }
                        }
                    }
                }
            }
        }
    }

    func stopVPN(completion: @escaping (Bool?) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { tunnelManagersInSettings, error in
            if let error = error {
                NSLog("Error (loadAllFromPreferences): \(error)")
                completion(false)
                return
            }

            if let tunnelManager = tunnelManagersInSettings?.first {
                guard let session = tunnelManager.connection as? NETunnelProviderSession else {
                    NSLog("tunnelManager.connection is invalid")
                    completion(false)
                    return
                }
                switch session.status {
                case .connected, .connecting, .reasserting:
                    NSLog("Stopping the tunnel")
                    session.stopTunnel()
                    completion(true)
                default:
                    completion(false)
                }
            } else {
                completion(false)
            }
        }
    }
}
