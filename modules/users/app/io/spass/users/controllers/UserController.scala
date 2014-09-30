package io.spass.users.controllers

import play.api.libs.json.Json
import play.api.mvc.Action
import resource._
import securesocial.core.{RuntimeEnvironment, SecureSocial}
import io.spass.users.models.BasicUser
import io.spass.web.models.{Navigation, NavigationItem, NavigationMenu}

import scala.io.Source
import scala.util.Random
import play.api.Logger

class UserController(override implicit val env: RuntimeEnvironment[BasicUser]) extends SecureSocial[BasicUser] {
  val logger = Logger(getClass)

  def navigation() = SecuredAction { implicit request =>
    Ok(Navigation("default", menus = Seq(
      NavigationMenu(items = Seq(NavigationItem("Change Password", "#/password")), position = "left"),
      NavigationMenu(items = Seq(NavigationItem("Sign Out", "#/logout")), position = "right")
    )).json)
  }

  def generateName() = Action { implicit request =>
    Ok(Json.stringify(Json.obj(
      "firstName" -> getRandomName("/names/firstname.txt"),
      "lastName" -> getRandomName("/names/lastname.txt")
    )))
  }

  def getRandomName(path: String): String = {
    managedSource(path) acquireAndGet {
      sizeSource =>
        val size = sizeSource.getLines().size
        managedSource(path) acquireAndGet {
          nameSource =>
            nameSource.getLines().drop(Random.nextInt(size) - 1).next().capitalize
        }
    }
  }

  def managedSource(classpath: String): ManagedResource[Source] = {
    managed(Source.fromInputStream(getClass.getResourceAsStream(classpath)))
  }

  def home() = SecuredAction { implicit request =>
    Ok(request.user.main.fullName.getOrElse("Full Name"))
  }
}