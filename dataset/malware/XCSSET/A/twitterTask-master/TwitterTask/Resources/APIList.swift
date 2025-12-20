
//
//  APILIst.swift
//  TwitterTask
//
//  Created by Ragul on 03/03/20.
//  Copyright © 2020 Ragul. All rights reserved.
//

import Foundation

enum APIList: String {
    
    case auth
    case tweets
    case timeLine
    
    var apiString:String{
        switch self {
        case .auth:
            return "\(Constants.baseUrl)/oauth2/token"
        case .tweets:
            return "\(Constants.baseUrl)/1.1/search/tweets.json"
        case .timeLine:
            return "\(Constants.baseUrl)/1.1/statuses/user_timeline.json"
        }
    }
    
}
