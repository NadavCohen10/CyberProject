//
//  EmptyData.swift
//  TwitterTask
//
//  Created by Ragul on 03/03/20.
//  Copyright © 2020 Ragul. All rights reserved.
//

import Foundation
import UIKit

class EmptyData: UIView {
    
    lazy var labelTitle:UILabel = {
        let title = UILabel()
        title.translatesAutoresizingMaskIntoConstraints = false
        title.textAlignment = .center
        title.numberOfLines = 0
        title.lineBreakMode = .byWordWrapping
        return title
    }()
    
    override init(frame: CGRect) {
        super.init(frame: frame)
        self.addSubview(labelTitle)
    }
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func layoutSubviews() {
        super.layoutSubviews()
        setConstraints()
    }
    
    func setConstraints() {
        //labelTitle
        labelTitle.centerYAnchor.constraint(equalTo: (labelTitle.superview!.centerYAnchor)).isActive = true
        labelTitle.centerXAnchor.constraint(equalTo: (labelTitle.superview!.centerXAnchor)).isActive = true
        labelTitle.leftAnchor.constraint(equalTo: (labelTitle.superview!.leftAnchor),constant:20).isActive = true
        labelTitle.rightAnchor.constraint(equalTo: (labelTitle.superview!.rightAnchor),constant:-20).isActive = true
    }
}
