//
//  Resources.swift
//  TwitterTask
//
//  Created by Ragul on 03/03/20.
//  Copyright © 2020 Ragul. All rights reserved.
//

import Foundation
import UIKit

extension String {
    func base64Encoded() -> String? {
        return data(using: .utf8)?.base64EncodedString()
    }
}

extension Parameters {
    var queryString: String {
        var output: String = ""
        for (key,value) in self {
            output +=  "\(key)=\(value)&"
        }
        output = String(output.dropLast())
        return output
    }
}

extension UIView {
    
    func setRadius(radius: CGFloat? = nil) {
        self.layer.masksToBounds = true
        self.layer.cornerRadius = radius ?? self.frame.height/2
    }
    
    func setBorder(width: CGFloat, color: UIColor) {
        self.layer.borderWidth = width
        self.layer.borderColor = color.cgColor
    }
}

extension UITableView {
    func reloadInMain() {
        DispatchQueue.main.async {
            self.reloadData()
        }
    }
    
    func setEmptyData(string: String) {
        let emptyDataView = EmptyData(frame: self.bounds)
        emptyDataView.labelTitle.text = string
        self.backgroundView = emptyDataView
    }
}

extension UIImageView {
    func downloaded(from url: URL, contentMode mode: UIView.ContentMode = .scaleAspectFit) {
        contentMode = mode
        URLSession.shared.dataTask(with: url) { data, response, error in
            guard
                let httpURLResponse = response as? HTTPURLResponse, httpURLResponse.statusCode == 200,
                let mimeType = response?.mimeType, mimeType.hasPrefix("image"),
                let data = data, error == nil,
                let image = UIImage(data: data)
                else { return }
            DispatchQueue.main.async() {
                self.image = image
            }
            }.resume()
    }
    
    func downloaded(from link: String, contentMode mode: UIView.ContentMode = .scaleAspectFit) {  // for swift 4.2 syntax just use ===> mode: UIView.ContentMode
        guard let url = URL(string: link) else { return }
        downloaded(from: url, contentMode: mode)
    }
}
