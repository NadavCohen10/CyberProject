//
//  TweetsController.swift
//  TwitterTask
//
//  Created by Ragul on 03/03/20.
//  Copyright © 2020 Ragul. All rights reserved.
//

import UIKit

class TweetsController: UIViewController {
    
    @IBOutlet weak var tableView: UITableView!
    @IBOutlet weak var searchBar: UISearchBar!
    var searchText : String?
    var tweets:[Statuses]?
    var timer : Timer?
    override func viewDidLoad() {
        super.viewDidLoad()
        tableView.register(UINib(nibName: "TweetCell", bundle: nil), forCellReuseIdentifier: "TweetCell")
        getAuth()
    }
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        self.navigationController?.navigationItem.hidesBackButton = true
        self.title = Constants.tweets
        searchBar.placeholder = Constants.searchByHashTag
    }
    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        self.timer?.invalidate()
    }
}

//MARK: Methods

extension TweetsController {
    
    func getAuth() {
        WebService.shared.makeAPICall(type: AuthData.self, url: .auth, method: .post, param: ["grant_type":"client_credentials"]) { (success, error) in
            if error == nil,let authData = success {
                AppManager.shared.accessToken = authData.access_token
            }else{
                print(error ?? "")
            }
        }
    }
    
    func getTweets(searchString: String) {
        WebService.shared.makeAPICall(type: SearchData.self, url: .tweets, method: .get, param: ["q":searchString]) { [weak self](success, error) in
            if error == nil, let status = success?.statuses {
                guard let wSelf = self else {
                    return
                }
                wSelf.tweets = status
                guard let wTableView = wSelf.tableView else {
                    return
                }
                wTableView.reloadInMain()
            }else{
                print(error ?? "")
            }
        }
    }
    
    @objc func refreshEvery3Secs(){
        if let searchText = self.searchText{
            getTweets(searchString: searchText)
        }
    }
}

//MARK:- Tableview

extension TweetsController: UITableViewDelegate, UITableViewDataSource {
    
    func numberOfSections(in tableView: UITableView) -> Int {
        return 1
    }
    
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        if self.tweets?.count == 0 {
            self.tableView.setEmptyData(string: Constants.noResultsFound)
        }else{
            self.tableView.backgroundView = nil
        }
        return self.tweets?.count ?? 0
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        if let cell:TweetCell = self.tableView.dequeueReusableCell(withIdentifier: "TweetCell") as? TweetCell,let values = self.tweets?[indexPath.row] {
            cell.setValues(values: values)
            return cell
        }
        return UITableViewCell()
    }
    
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        let vc = self.storyboard?.instantiateViewController(withIdentifier: "UserDetailController") as! UserDetailController
        vc.userId = self.tweets?[indexPath.row].user?.id_str
        vc.screenName = self.tweets?[indexPath.row].user?.screen_name
        vc.userDetail = self.tweets?[indexPath.row].user
        self.navigationController?.pushViewController(vc, animated: true)
    }
}

//MARK: - UISearchBarDelegate

extension TweetsController: UISearchBarDelegate {
    
    func searchBarTextDidEndEditing(_ searchBar: UISearchBar) {
        if let searchText = searchBar.text{
            if searchText != "" {
                getTweets(searchString: searchText)
                self.searchText = searchText
                self.timer = Timer.scheduledTimer(timeInterval: 3.0, target: self,selector: #selector(self.refreshEvery3Secs), userInfo: nil, repeats: true)

            }
        }
    }
    
    func searchBarSearchButtonClicked(_ searchBar: UISearchBar) {
        searchBar.searchTextField.resignFirstResponder()
    }
}
