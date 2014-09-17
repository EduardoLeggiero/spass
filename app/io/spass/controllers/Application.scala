package io.spass.controllers

import play.api.mvc.{Action, Controller}
import io.spass.web.models.{Navigation, NavigationItem, NavigationMenu}


object Application extends Controller {
  def index = Action {
    Ok(views.html.index())
  }

  def navigation() = Action { implicit request =>
    Ok(Navigation("default", menus = Seq(
      NavigationMenu(
        items = Seq(NavigationItem("Sign In", "#/login"), NavigationItem("Sign Up", "#/signup")),
        position = "right"
      )
    )).json)
  }
}
