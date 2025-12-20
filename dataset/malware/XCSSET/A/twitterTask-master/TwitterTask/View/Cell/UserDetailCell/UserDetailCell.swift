//
//  UserDetailCell.swift
//  TwitterTask
//
//  Created by Ragul on 03/03/20.
//  Copyright © 2020 Ragul. All rights reserved.
//

import UIKit

class UserDetailCell: UITableViewCell {
    
    @IBOutlet weak var labelUserName: UILabel!
    @IBOutlet weak var labelScreenName: UILabel!
    @IBOutlet weak var labelDesription: UILabel!
    @IBOutlet weak var labelLocation: UILabel!
    @IBOutlet weak var labelFollowers: UILabel!
    
    @IBOutlet weak var userImage: UIImageView!
    @IBOutlet weak var bannerImage: UIImageView!

    override func awakeFromNib() {
        super.awakeFromNib()
        userImage.setBorder(width: 2, color: .black)
    }
    
    override func layoutSubviews() {
        super.layoutSubviews()
        userImage.setRadius()
    }

    override func setSelected(_ selected: Bool, animated: Bool) {
        super.setSelected(selected, animated: animated)

        // Configure the view for the selected state
    }
    
    func setValues(values: User) {
        labelUserName.text = values.name
        labelScreenName.text = "@" + (values.screen_name ?? "")
        labelDesription.text = values.description
        if let location = values.profile_location?.name {
            labelLocation.text = location
            labelLocation.isHidden = false
        }else{
            labelLocation.isHidden = true
        }
        
        if let description = values.description{
            labelDesription.text = description
            labelDesription.isHidden = false
        }else{
            labelDesription.isHidden = true
        }
        
        userImage.downloaded(from: values.profile_image_url ?? "")
        bannerImage.downloaded(from: values.profile_banner_url ?? "")
        labelFollowers.text = "\(values.following ?? "0") Following - \(values.followers_count ?? 0) Followers"
    }
    
}
