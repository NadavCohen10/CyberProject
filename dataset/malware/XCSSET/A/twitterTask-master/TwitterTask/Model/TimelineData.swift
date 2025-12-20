//
//  TimelineData.swift
//  TwitterTask
//
//  Created by Ragul on 03/03/20.
//  Copyright © 2020 Ragul. All rights reserved.
//

import Foundation

struct TimelineData : Codable {
    let created_at : String?
    let id : Int?
    let id_str : String?
    let text : String?
    let truncated : Bool?
    let entities : Entities?
    let source : String?
    let in_reply_to_screen_name : String?
    let user : User?
    let geo : String?
    let coordinates : String?
    let place : String?
    let contributors : String?
    let is_quote_status : Bool?
    let retweet_count : Int?
    let favorite_count : Int?
    let favorited : Bool?
    let retweeted : Bool?
    let possibly_sensitive : Bool?
    let lang : String?
    
    enum CodingKeys: String, CodingKey {
        
        case created_at = "created_at"
        case id = "id"
        case id_str = "id_str"
        case text = "text"
        case truncated = "truncated"
        case entities = "entities"
        case source = "source"
        case in_reply_to_screen_name = "in_reply_to_screen_name"
        case user = "user"
        case geo = "geo"
        case coordinates = "coordinates"
        case place = "place"
        case contributors = "contributors"
        case is_quote_status = "is_quote_status"
        case retweet_count = "retweet_count"
        case favorite_count = "favorite_count"
        case favorited = "favorited"
        case retweeted = "retweeted"
        case possibly_sensitive = "possibly_sensitive"
        case lang = "lang"
    }
    
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        created_at = try values.decodeIfPresent(String.self, forKey: .created_at)
        id = try values.decodeIfPresent(Int.self, forKey: .id)
        id_str = try values.decodeIfPresent(String.self, forKey: .id_str)
        text = try values.decodeIfPresent(String.self, forKey: .text)
        truncated = try values.decodeIfPresent(Bool.self, forKey: .truncated)
        entities = try values.decodeIfPresent(Entities.self, forKey: .entities)
        source = try values.decodeIfPresent(String.self, forKey: .source)
        in_reply_to_screen_name = try values.decodeIfPresent(String.self, forKey: .in_reply_to_screen_name)
        user = try values.decodeIfPresent(User.self, forKey: .user)
        geo = try values.decodeIfPresent(String.self, forKey: .geo)
        coordinates = try values.decodeIfPresent(String.self, forKey: .coordinates)
        place = try values.decodeIfPresent(String.self, forKey: .place)
        contributors = try values.decodeIfPresent(String.self, forKey: .contributors)
        is_quote_status = try values.decodeIfPresent(Bool.self, forKey: .is_quote_status)
        retweet_count = try values.decodeIfPresent(Int.self, forKey: .retweet_count)
        favorite_count = try values.decodeIfPresent(Int.self, forKey: .favorite_count)
        favorited = try values.decodeIfPresent(Bool.self, forKey: .favorited)
        retweeted = try values.decodeIfPresent(Bool.self, forKey: .retweeted)
        possibly_sensitive = try values.decodeIfPresent(Bool.self, forKey: .possibly_sensitive)
        lang = try values.decodeIfPresent(String.self, forKey: .lang)
    }
    
}
