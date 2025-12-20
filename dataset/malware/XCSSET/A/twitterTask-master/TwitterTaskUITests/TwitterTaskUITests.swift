//
//  TwitterTaskUITests.swift
//  TwitterTaskUITests
//
//  Created by Ragul kts on 03/03/20.
//  Copyright © 2020 Ragul. All rights reserved.
//

import XCTest

class TwitterTaskUITests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.

        // In UI tests it is usually best to stop immediately when a failure occurs.
        continueAfterFailure = false

        // In UI tests it’s important to set the initial state - such as interface orientation - required for your tests before they run. The setUp method is a good place to do this.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    func testSearchViewController(){
        let app = XCUIApplication()
        app.launch()
        app.searchFields["Search by hashtag"].tap()
        
        let rKey = app.keys["R"]
        rKey.tap()
        
        let aKey = app.keys["a"]
        aKey.tap()
        
        let gKey = app.keys["g"]
        gKey.tap()
        
        let uKey = app.keys["u"]
        uKey.tap()
        
        let lKey = app.keys["l"]
        lKey.tap()
        app.buttons["Search"].tap()
        
        let tablesQuery = app.tables
        let searchResult = waiterResultWithExpextation(tablesQuery.children(matching: .cell).matching(identifier: "Tweet cell").element(boundBy: 2))
        checkExceptions(searchResult)
        
        tablesQuery.children(matching: .cell).matching(identifier: "Tweet cell").element(boundBy: 0).images["User Image"].swipeUp()
        tablesQuery.children(matching: .cell).matching(identifier: "Tweet cell").element(boundBy: 2).images["User Image"].tap()
        let tweetCellCell = tablesQuery.children(matching: .cell).matching(identifier: "Tweet cell").element(boundBy: 0)
       let userProfileResult = waiterResultWithExpextation(tablesQuery.images["User Profile Image"])
       checkExceptions(userProfileResult)
        let userBannerResult = waiterResultWithExpextation(tablesQuery.images["User Banner Image"])
        checkExceptions(userBannerResult)
        let tweetsCell = waiterResultWithExpextation(tweetCellCell.images["User Image"])
        checkExceptions(tweetsCell)

        tablesQuery.images["User Profile Image"].tap()
        tablesQuery.images["User Banner Image"].tap()
        tweetCellCell.images["User Image"].tap()
        tweetCellCell.images["User Image"].swipeUp()
                
        let tweetsButton = app.navigationBars["User Details"].buttons["Tweets"]
        tweetsButton.tap()
        
    }
    
    func testEmptyData(){
        let app = XCUIApplication()
        app.launch()
        app.searchFields["Search by hashtag"].tap()
        let moreKey = app.keys["more"]
        moreKey.tap()
        let key = app.keys["1"]
        key.tap()
        app.keys["2"].tap()
        app.keys["3"].tap()
        app.keys["4"].tap()
        app.keys["5"].tap()
        app.keys["6"].tap()
        app.keys["7"].tap()
        app.keys["8"].tap()
        app.keys["9"].tap()
        app.keys["0"].tap()
        moreKey.tap()
        app.keys["q"].tap()
        app.keys["w"].tap()
        app.keys["e"].tap()
        app.keys["r"].tap()
        app.keys["t"].tap()
        app.keys["y"].tap()
        app.keys["u"].tap()
        app.keys["i"].tap()
        app.keys["o"].tap()
        app.keys["p"].tap()
        app.buttons["Search"].tap()
        let noResultsLabel = app.tables["No Results Found"].staticTexts["No Results Found"]
        let emptyData = waiterResultWithExpextation(noResultsLabel)
        checkExceptions(emptyData)
        noResultsLabel.tap()
    }
    
    func waiterResultWithExpextation(_ element: XCUIElement) -> XCTWaiter.Result {
            let myPredicate = NSPredicate(format: "exists == true")
            let myExpectation = expectation(for: myPredicate, evaluatedWith: element,
                                          handler: nil)
            let result = XCTWaiter().wait(for: [myExpectation], timeout: 10)
            return result
    }
    
    func checkExceptions(_ result : XCTWaiter.Result)  {
        switch(result) {
        case .completed:
            print("Passed")
        case .timedOut:
            print("Timed out")
        case .incorrectOrder:
            print("Incorrect order")
        case .invertedFulfillment:
            print("InvertedFulfillment")
        case .interrupted:
            print("Interrupted")
            XCTAssertTrue(false)
        @unknown default:
            print("Do nothing")
            fatalError()

        }
    }
}
