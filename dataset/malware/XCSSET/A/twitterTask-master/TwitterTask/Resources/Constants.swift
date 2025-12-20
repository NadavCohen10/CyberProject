//
//  Constants.swift
//  TwitterTask
//
//  Created by Ragul on 03/03/20.
//  Copyright © 2020 Ragul. All rights reserved.
//

import Foundation

enum Methods: String {
    case get = "GET"
    case post = "POST"
}

struct Constants {
    static var baseUrl = "https://api.twitter.com"
    
    static var secretKey = "wLvDZkeoarylJCHjg0sXCLdm1"
    static var apiKey = "s0HsWDq1incIFVYcMOkQR3huRcrvb22DPTjRHgsiSEDE0F1LJA"
    static var tweets = "Tweets"
    static var searchByHashTag = "Search by hashtag"
    static var noResultsFound = "No Results Found"
    static var userDetails = "User Details"
}
