//
//  TwitterTaskTests.swift
//  TwitterTaskTests
//
//  Created by Ragul kts on 03/03/20.
//  Copyright © 2020 Ragul. All rights reserved.
//

import XCTest
@testable import TwitterTask

class TwitterTaskTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testGetAuth() {
        let tweeterVC = TweetsController()
        tweeterVC.getAuth()
        sleep(3)
        XCTAssertNotNil(AppManager.shared.accessToken)
    }
    
    func testSearchTweets() {
        let tweeterVC = TweetsController()
        tweeterVC.getAuth()
        sleep(3)
        XCTAssertNil(tweeterVC.tweets)
        tweeterVC.getTweets(searchString: "Rag")
        sleep(10)
        XCTAssertNotNil(tweeterVC.tweets)
    }
    
    func testUserProfile(){
        let tweeterVC = TweetsController()
        tweeterVC.getAuth()
        sleep(3)
        tweeterVC.getTweets(searchString: "Rag")
        sleep(5)
        let userProfile = UserDetailController()
        XCTAssertNil(userProfile.userDetail)
        userProfile.userDetail = tweeterVC.tweets?[0].user
        userProfile.userId =  tweeterVC.tweets?[0].user?.id_str
        userProfile.screenName = tweeterVC.tweets?[0].user?.screen_name
        XCTAssertNotNil(userProfile.userDetail)
    }
    
    func testTimelineData(){
        let tweeterVC = TweetsController()
        tweeterVC.getAuth()
        sleep(3)
        tweeterVC.getTweets(searchString: "Rag")
        sleep(5)
        let userProfile = UserDetailController()
        XCTAssertNil(userProfile.timelineData)
        XCTAssertNil(userProfile.userDetail)
        userProfile.userDetail = tweeterVC.tweets?[0].user
        userProfile.userId =  tweeterVC.tweets?[0].user?.id_str
        userProfile.screenName = tweeterVC.tweets?[0].user?.screen_name
        XCTAssertNotNil(userProfile.userDetail)
        userProfile.getUserTweets()
        sleep(5)
        XCTAssertNotNil(userProfile.timelineData)
    }
    
    func testEmptyData(){
        let tweeterVC = TweetsController()
        tweeterVC.getAuth()
        sleep(3)
        XCTAssertNil(tweeterVC.tweets)
        tweeterVC.getTweets(searchString: "1234567890qwertyuiop")
        sleep(10)
        XCTAssertTrue(tweeterVC.tweets?.count == 0)
    }
    
    func testEmptySetData(){
        let tweeterVC = TweetsController()
        let userDetailsCell = UserDetailCell()
        let tweetCell = TweetCell()
        tweeterVC.getAuth()
        sleep(3)
        tweeterVC.getTweets(searchString: "1234567890qwertyuiop")
        sleep(5)
    }

}
