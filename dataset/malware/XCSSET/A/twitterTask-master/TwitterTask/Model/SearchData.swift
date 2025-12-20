//
//  SearchData.swift
//  TwitterTask
//
//  Created by Ragul on 03/03/20.
//  Copyright © 2020 Ragul. All rights reserved.
//

import Foundation

struct SearchData : Codable {
    let statuses : [Statuses]?
    let search_metadata : Search_metadata?
    
    enum CodingKeys: String, CodingKey {
        
        case statuses = "statuses"
        case search_metadata = "search_metadata"
    }
    
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        statuses = try values.decodeIfPresent([Statuses].self, forKey: .statuses)
        search_metadata = try values.decodeIfPresent(Search_metadata.self, forKey: .search_metadata)
    }
    
}


struct Metadata : Codable {
    let iso_language_code : String?
    let result_type : String?
    
    enum CodingKeys: String, CodingKey {
        
        case iso_language_code = "iso_language_code"
        case result_type = "result_type"
    }
    
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        iso_language_code = try values.decodeIfPresent(String.self, forKey: .iso_language_code)
        result_type = try values.decodeIfPresent(String.self, forKey: .result_type)
    }
    
}


struct Retweeted_status : Codable {
    let created_at : String?
    let id : Int?
    let id_str : String?
    let text : String?
    let truncated : Bool?
    let entities : Entities?
    let metadata : Metadata?
    let source : String?
    let in_reply_to_screen_name : String?
    let user : User?
    let geo : String?
    let coordinates : String?
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
        case metadata = "metadata"
        case source = "source"
        case in_reply_to_screen_name = "in_reply_to_screen_name"
        case user = "user"
        case geo = "geo"
        case coordinates = "coordinates"
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
        metadata = try values.decodeIfPresent(Metadata.self, forKey: .metadata)
        source = try values.decodeIfPresent(String.self, forKey: .source)
        in_reply_to_screen_name = try values.decodeIfPresent(String.self, forKey: .in_reply_to_screen_name)
        user = try values.decodeIfPresent(User.self, forKey: .user)
        geo = try values.decodeIfPresent(String.self, forKey: .geo)
        coordinates = try values.decodeIfPresent(String.self, forKey: .coordinates)
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

struct Search_metadata : Codable {
    let completed_in : Double?
    let max_id : Int?
    let max_id_str : String?
    let next_results : String?
    let query : String?
    let refresh_url : String?
    let count : Int?
    let since_id : Int?
    let since_id_str : String?
    
    enum CodingKeys: String, CodingKey {
        
        case completed_in = "completed_in"
        case max_id = "max_id"
        case max_id_str = "max_id_str"
        case next_results = "next_results"
        case query = "query"
        case refresh_url = "refresh_url"
        case count = "count"
        case since_id = "since_id"
        case since_id_str = "since_id_str"
    }
    
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        completed_in = try values.decodeIfPresent(Double.self, forKey: .completed_in)
        max_id = try values.decodeIfPresent(Int.self, forKey: .max_id)
        max_id_str = try values.decodeIfPresent(String.self, forKey: .max_id_str)
        next_results = try values.decodeIfPresent(String.self, forKey: .next_results)
        query = try values.decodeIfPresent(String.self, forKey: .query)
        refresh_url = try values.decodeIfPresent(String.self, forKey: .refresh_url)
        count = try values.decodeIfPresent(Int.self, forKey: .count)
        since_id = try values.decodeIfPresent(Int.self, forKey: .since_id)
        since_id_str = try values.decodeIfPresent(String.self, forKey: .since_id_str)
    }
    
}

struct Statuses : Codable {
    let created_at : String?
    let id : Int?
    let id_str : String?
    let text : String?
    let truncated : Bool?
    let entities : Entities?
    let metadata : Metadata?
    let source : String?
    let in_reply_to_screen_name : String?
    let user : User?
    let geo : String?
    let coordinates : String?
    let contributors : String?
    let is_quote_status : Bool?
    let retweet_count : Int?
    let favorite_count : Int?
    let favorited : Bool?
    let retweeted : Bool?
    let lang : String?
    
    enum CodingKeys: String, CodingKey {
        
        case created_at = "created_at"
        case id = "id"
        case id_str = "id_str"
        case text = "text"
        case truncated = "truncated"
        case entities = "entities"
        case metadata = "metadata"
        case source = "source"
        case in_reply_to_screen_name = "in_reply_to_screen_name"
        case user = "user"
        case geo = "geo"
        case coordinates = "coordinates"
        case contributors = "contributors"
        case is_quote_status = "is_quote_status"
        case retweet_count = "retweet_count"
        case favorite_count = "favorite_count"
        case favorited = "favorited"
        case retweeted = "retweeted"
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
        metadata = try values.decodeIfPresent(Metadata.self, forKey: .metadata)
        source = try values.decodeIfPresent(String.self, forKey: .source)
        in_reply_to_screen_name = try values.decodeIfPresent(String.self, forKey: .in_reply_to_screen_name)
        user = try values.decodeIfPresent(User.self, forKey: .user)
        geo = try values.decodeIfPresent(String.self, forKey: .geo)
        coordinates = try values.decodeIfPresent(String.self, forKey: .coordinates)
        contributors = try values.decodeIfPresent(String.self, forKey: .contributors)
        is_quote_status = try values.decodeIfPresent(Bool.self, forKey: .is_quote_status)
        retweet_count = try values.decodeIfPresent(Int.self, forKey: .retweet_count)
        favorite_count = try values.decodeIfPresent(Int.self, forKey: .favorite_count)
        favorited = try values.decodeIfPresent(Bool.self, forKey: .favorited)
        retweeted = try values.decodeIfPresent(Bool.self, forKey: .retweeted)
        lang = try values.decodeIfPresent(String.self, forKey: .lang)
    }
    
}

struct Urls : Codable {
    let url : String?
    let expanded_url : String?
    let display_url : String?
    let indices : [Int]?
    
    enum CodingKeys: String, CodingKey {
        
        case url = "url"
        case expanded_url = "expanded_url"
        case display_url = "display_url"
        case indices = "indices"
    }
    
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        url = try values.decodeIfPresent(String.self, forKey: .url)
        expanded_url = try values.decodeIfPresent(String.self, forKey: .expanded_url)
        display_url = try values.decodeIfPresent(String.self, forKey: .display_url)
        indices = try values.decodeIfPresent([Int].self, forKey: .indices)
    }
    
}

struct User_mentions : Codable {
    let screen_name : String?
    let name : String?
    let id : Int?
    let id_str : String?
    let indices : [Int]?
    
    enum CodingKeys: String, CodingKey {
        
        case screen_name = "screen_name"
        case name = "name"
        case id = "id"
        case id_str = "id_str"
        case indices = "indices"
    }
    
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        screen_name = try values.decodeIfPresent(String.self, forKey: .screen_name)
        name = try values.decodeIfPresent(String.self, forKey: .name)
        id = try values.decodeIfPresent(Int.self, forKey: .id)
        id_str = try values.decodeIfPresent(String.self, forKey: .id_str)
        indices = try values.decodeIfPresent([Int].self, forKey: .indices)
    }
    
}


struct User : Codable {
    let id : Int?
    let id_str : String?
    let name : String?
    let screen_name : String?
    let location : String?
    let description : String?
    let url : String?
    let entities : Entities?
    let protected : Bool?
    let followers_count : Int?
    let friends_count : Int?
    let listed_count : Int?
    let created_at : String?
    let favourites_count : Int?
    let utc_offset : String?
    let time_zone : String?
    let geo_enabled : Bool?
    let verified : Bool?
    let statuses_count : Int?
    let lang : String?
    let contributors_enabled : Bool?
    let is_translator : Bool?
    let is_translation_enabled : Bool?
    let profile_background_color : String?
    let profile_background_image_url : String?
    let profile_background_image_url_https : String?
    let profile_background_tile : Bool?
    let profile_image_url : String?
    let profile_image_url_https : String?
    let profile_banner_url : String?
    let profile_link_color : String?
    let profile_sidebar_border_color : String?
    let profile_sidebar_fill_color : String?
    let profile_text_color : String?
    let profile_use_background_image : Bool?
    let has_extended_profile : Bool?
    let default_profile : Bool?
    let default_profile_image : Bool?
    let following : String?
    let follow_request_sent : String?
    let notifications : String?
    let translator_type : String?
    let profile_location: ProfileLocation?
    
    enum CodingKeys: String, CodingKey {
        
        case id = "id"
        case id_str = "id_str"
        case name = "name"
        case screen_name = "screen_name"
        case location = "location"
        case description = "description"
        case url = "url"
        case entities = "entities"
        case protected = "protected"
        case followers_count = "followers_count"
        case friends_count = "friends_count"
        case listed_count = "listed_count"
        case created_at = "created_at"
        case favourites_count = "favourites_count"
        case utc_offset = "utc_offset"
        case time_zone = "time_zone"
        case geo_enabled = "geo_enabled"
        case verified = "verified"
        case statuses_count = "statuses_count"
        case lang = "lang"
        case contributors_enabled = "contributors_enabled"
        case is_translator = "is_translator"
        case is_translation_enabled = "is_translation_enabled"
        case profile_background_color = "profile_background_color"
        case profile_background_image_url = "profile_background_image_url"
        case profile_background_image_url_https = "profile_background_image_url_https"
        case profile_background_tile = "profile_background_tile"
        case profile_image_url = "profile_image_url"
        case profile_image_url_https = "profile_image_url_https"
        case profile_banner_url = "profile_banner_url"
        case profile_link_color = "profile_link_color"
        case profile_sidebar_border_color = "profile_sidebar_border_color"
        case profile_sidebar_fill_color = "profile_sidebar_fill_color"
        case profile_text_color = "profile_text_color"
        case profile_use_background_image = "profile_use_background_image"
        case has_extended_profile = "has_extended_profile"
        case default_profile = "default_profile"
        case default_profile_image = "default_profile_image"
        case following = "following"
        case follow_request_sent = "follow_request_sent"
        case notifications = "notifications"
        case translator_type = "translator_type"
        case profile_location = "profile_location"
    }
    
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decodeIfPresent(Int.self, forKey: .id)
        id_str = try values.decodeIfPresent(String.self, forKey: .id_str)
        name = try values.decodeIfPresent(String.self, forKey: .name)
        screen_name = try values.decodeIfPresent(String.self, forKey: .screen_name)
        location = try values.decodeIfPresent(String.self, forKey: .location)
        description = try values.decodeIfPresent(String.self, forKey: .description)
        url = try values.decodeIfPresent(String.self, forKey: .url)
        entities = try values.decodeIfPresent(Entities.self, forKey: .entities)
        protected = try values.decodeIfPresent(Bool.self, forKey: .protected)
        followers_count = try values.decodeIfPresent(Int.self, forKey: .followers_count)
        friends_count = try values.decodeIfPresent(Int.self, forKey: .friends_count)
        listed_count = try values.decodeIfPresent(Int.self, forKey: .listed_count)
        created_at = try values.decodeIfPresent(String.self, forKey: .created_at)
        favourites_count = try values.decodeIfPresent(Int.self, forKey: .favourites_count)
        utc_offset = try values.decodeIfPresent(String.self, forKey: .utc_offset)
        time_zone = try values.decodeIfPresent(String.self, forKey: .time_zone)
        geo_enabled = try values.decodeIfPresent(Bool.self, forKey: .geo_enabled)
        verified = try values.decodeIfPresent(Bool.self, forKey: .verified)
        statuses_count = try values.decodeIfPresent(Int.self, forKey: .statuses_count)
        lang = try values.decodeIfPresent(String.self, forKey: .lang)
        contributors_enabled = try values.decodeIfPresent(Bool.self, forKey: .contributors_enabled)
        is_translator = try values.decodeIfPresent(Bool.self, forKey: .is_translator)
        is_translation_enabled = try values.decodeIfPresent(Bool.self, forKey: .is_translation_enabled)
        profile_background_color = try values.decodeIfPresent(String.self, forKey: .profile_background_color)
        profile_background_image_url = try values.decodeIfPresent(String.self, forKey: .profile_background_image_url)
        profile_background_image_url_https = try values.decodeIfPresent(String.self, forKey: .profile_background_image_url_https)
        profile_background_tile = try values.decodeIfPresent(Bool.self, forKey: .profile_background_tile)
        profile_image_url = try values.decodeIfPresent(String.self, forKey: .profile_image_url)
        profile_image_url_https = try values.decodeIfPresent(String.self, forKey: .profile_image_url_https)
        profile_banner_url = try values.decodeIfPresent(String.self, forKey: .profile_banner_url)
        profile_link_color = try values.decodeIfPresent(String.self, forKey: .profile_link_color)
        profile_sidebar_border_color = try values.decodeIfPresent(String.self, forKey: .profile_sidebar_border_color)
        profile_sidebar_fill_color = try values.decodeIfPresent(String.self, forKey: .profile_sidebar_fill_color)
        profile_text_color = try values.decodeIfPresent(String.self, forKey: .profile_text_color)
        profile_use_background_image = try values.decodeIfPresent(Bool.self, forKey: .profile_use_background_image)
        has_extended_profile = try values.decodeIfPresent(Bool.self, forKey: .has_extended_profile)
        default_profile = try values.decodeIfPresent(Bool.self, forKey: .default_profile)
        default_profile_image = try values.decodeIfPresent(Bool.self, forKey: .default_profile_image)
        following = try values.decodeIfPresent(String.self, forKey: .following)
        follow_request_sent = try values.decodeIfPresent(String.self, forKey: .follow_request_sent)
        notifications = try values.decodeIfPresent(String.self, forKey: .notifications)
        translator_type = try values.decodeIfPresent(String.self, forKey: .translator_type)
        profile_location = try values.decodeIfPresent(ProfileLocation.self, forKey: .profile_location)
    }
    
}

struct Description : Codable {
    let urls : [Urls]?
    
    enum CodingKeys: String, CodingKey {
        
        case urls = "urls"
    }
    
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        urls = try values.decodeIfPresent([Urls].self, forKey: .urls)
    }
    
}

struct Entities : Codable {
    let description : Description?
    
    enum CodingKeys: String, CodingKey {
        
        case description = "description"
    }
    
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        description = try values.decodeIfPresent(Description.self, forKey: .description)
    }
    
}

struct ProfileLocation : Codable {
    let full_name : String?
    let name: String?
    
    enum CodingKeys: String, CodingKey {
        
        case full_name = "full_name"
        case name = "name"
    }
    
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        full_name = try values.decodeIfPresent(String.self, forKey: .full_name)
        name = try values.decodeIfPresent(String.self, forKey: .name)
    }
    
}
