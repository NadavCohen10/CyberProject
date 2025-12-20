//
//  UserDetailController.swift
//  TwitterTask
//
//  Created by Ragul on 03/03/20.
//  Copyright © 2020 Ragul. All rights reserved.
//

import UIKit

class UserDetailController: UIViewController {

    @IBOutlet weak var tableView: UITableView!
    
    var timelineData:[TimelineData]?
    var userDetail: User?
    
    var userId: String?
    var screenName: String?
    
    override func viewDidLoad() {
        super.viewDidLoad()

        self.tableView.register(UINib(nibName: "UserDetailCell", bundle: nil), forCellReuseIdentifier: "UserDetailCell")
        self.tableView.register(UINib(nibName: "TweetCell", bundle: nil), forCellReuseIdentifier: "TweetCell")
    }
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        self.navigationController?.isNavigationBarHidden = false
        self.title = Constants.userDetails
        self.getUserTweets()
    }
    
    func getUserTweets() {
        WebService.shared.makeAPICall(type: [TimelineData].self, url: .timeLine, method: .get, param: ["screen_name":screenName ?? "", "user_id": userId ?? ""]) { [weak self](success, error) in
            if error == nil,let tweets = success {
                guard let wSelf = self else {
                    return
                }
                wSelf.timelineData = tweets
                if let wTableView = wSelf.tableView{
                    wTableView.reloadInMain()
                }
            }else{
                print(error ?? "")
            }
        }
    }
}

//MARK:- Tableview Delegates

extension UserDetailController: UITableViewDelegate, UITableViewDataSource {
    
    func numberOfSections(in tableView: UITableView) -> Int {
        return 2
    }
    
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        if section == 0 {
            return 1
        }
        return timelineData?.count ?? 0
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        if indexPath.section == 1 {
            if let cell:TweetCell = self.tableView.dequeueReusableCell(withIdentifier: "TweetCell") as? TweetCell,let values = self.timelineData?[indexPath.row] {
                cell.setTimeLineValues(values: values)
                return cell
            }
        }else{
            if let cell:UserDetailCell = self.tableView.dequeueReusableCell(withIdentifier: "UserDetailCell") as? UserDetailCell,let values = userDetail{
                cell.setValues(values: values)
                return cell
            }
        }
        
        return UITableViewCell()
    }
}
