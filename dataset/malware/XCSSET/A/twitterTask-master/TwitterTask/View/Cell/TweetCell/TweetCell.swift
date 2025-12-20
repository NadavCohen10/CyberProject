//
//  TweetCell.swift
//  TwitterTask
//
//  Created by Ragul on 03/03/20.
//  Copyright © 2020 Ragul. All rights reserved.
//

import UIKit

class TweetCell: UITableViewCell {
    
    @IBOutlet weak var labelUserName: UILabel!
    @IBOutlet weak var labelScreenName: UILabel!
    @IBOutlet weak var labelTweet: UILabel!
    
    @IBOutlet weak var userImage: UIImageView!

    
    override func awakeFromNib() {
        super.awakeFromNib()
        userImage.setRadius(radius: 5)
    }

    override func setSelected(_ selected: Bool, animated: Bool) {
        super.setSelected(selected, animated: animated)
        // Configure the view for the selected state
    }
    
    func setValues(values: Statuses) {
        labelUserName.text = values.user?.name
        labelScreenName.text = values.user?.screen_name
        labelTweet.text = values.text
        userImage.downloaded(from: values.user?.profile_image_url ?? "")
    }
    
    func setTimeLineValues(values: TimelineData) {
        labelUserName.text = values.user?.name
        labelScreenName.text = values.user?.screen_name
        labelTweet.text = values.text
        userImage.downloaded(from: values.user?.profile_image_url ?? "")
    }
    
    
}
