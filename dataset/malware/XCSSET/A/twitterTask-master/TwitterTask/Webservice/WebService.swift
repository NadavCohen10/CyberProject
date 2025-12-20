//
//  WebService.swift
//  BankGenieTask
//
//  Created by Ragul on 03/03/20.
//  Copyright © 2020 Ragul. All rights reserved.
//

import Foundation

typealias Parameters = [String:Any]

class WebService {
    
    static var shared = WebService()
    
    
    func makeAPICall<T:Decodable>(type:T.Type, url:APIList, method:Methods, param: Parameters,completion: @escaping ((_ success: T?,_ error: String?)->Void)) {
        var finalUrl = ""
        if method == .get {
            finalUrl = url.apiString + "?" + param.queryString
        }else{
            finalUrl = url.apiString
        }
        guard let todosURL = URL(string: finalUrl) else {
            completion(nil,"Error: cannot create URL")
            return
        }

        var urlRequest = URLRequest(url: todosURL)
        urlRequest.httpMethod = method.rawValue
        urlRequest.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        if url == .auth {
            urlRequest.setValue("Basic \(convertBase64())", forHTTPHeaderField: "Authorization")
        }else{
            urlRequest.setValue("Bearer \(AppManager.shared.accessToken ?? "")", forHTTPHeaderField: "Authorization")
        }
        
        if method == .post {
            urlRequest.httpBody = param.queryString.data(using: .utf8)
        }
        
        let session = URLSession.shared
        let task = session.dataTask(with: urlRequest) {
            (data, response, error) in
            guard error == nil else {
                completion(nil,error?.localizedDescription)
                return
            }
            guard let responseData = data else {
                completion(nil,"Error: did not receive data")
                return
            }
            do {
                let json = try JSONSerialization.jsonObject(with: responseData, options: []) as? [String:Any]
                print("\(url.apiString) \n\n \(json)")
                let genericModel = try JSONDecoder().decode(type, from: responseData)
                completion(genericModel, nil)
            } catch (let parseError) {
                print(parseError)
                completion(nil,parseError.localizedDescription)
                return
            }
        }
        task.resume()
    }
    
    private func convertBase64() -> String {
        return "\(Constants.secretKey):\(Constants.apiKey)".base64Encoded() ?? ""
    }
}

