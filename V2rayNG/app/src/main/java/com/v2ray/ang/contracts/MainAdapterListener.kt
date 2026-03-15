package com.v3a.ang.contracts

import com.v3a.ang.dto.ProfileItem

interface MainAdapterListener :BaseAdapterListener {

    fun onEdit(guid: String, position: Int, profile: ProfileItem)

    fun onSelectServer(guid: String)

    fun onShare(guid: String, profile: ProfileItem, position: Int, more: Boolean)

}