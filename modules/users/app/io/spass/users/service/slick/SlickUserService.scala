package io.spass.users.service.slick

import com.github.tototoshi.slick.JdbcJodaSupport._
import org.joda.time.DateTime
import play.api.Logger
import play.api.Play.current
import play.api.db.slick.DB
import securesocial.core._
import securesocial.core.providers.{MailToken, UsernamePasswordProvider}
import securesocial.core.services.SaveMode
import io.spass.users.models._
import UserTableQueries._

import scala.concurrent.Future
import scala.slick.driver.JdbcDriver.simple._

/**
 * @author Joseph Dessens
 * @since 2014-08-03
 */
class SlickUserService extends securesocial.core.services.UserService[BasicUser] {
  val logger: Logger = Logger(this.getClass)

  override def find(providerId: String, userId: String): Future[Option[BasicProfile]] = Future successful {
    DB withSession { implicit session =>
      profiles
        .filter(sp => sp.providerId === providerId && sp.userId === userId)
        .firstOption
        .map(sp => sp.basicProfile)
    }
  }

  override def findByEmailAndProvider(email: String, providerId: String): Future[Option[BasicProfile]] = Future successful {
    DB withSession { implicit session =>
      profiles
        .filter(sp => sp.email === email && sp.providerId === providerId)
        .firstOption
        .map(sp => sp.basicProfile)
    }
  }

  override def deleteToken(uuid: String): Future[Option[MailToken]] = Future successful {
    DB withSession { implicit session =>
      mailTokens.filter(_.uuid === uuid).firstOption.map(mt => {
        mailTokens.filter(_.uuid === uuid).delete
        mt
      })
    }
  }

  override def link(current: BasicUser, to: BasicProfile): Future[BasicUser] = Future successful {
    if (current.identities.exists(i => i.providerId == to.providerId && i.userId == to.userId)) {
      current
    } else {
      current.copy(identities = to :: current.identities)
    }
  }

  override def passwordInfoFor(user: BasicUser): Future[Option[PasswordInfo]] = Future successful {
    DB withSession { implicit session =>
      passwords.filter(_.userId === user.main.userId).firstOption.map(sp => sp.passwordInfo)
    }
  }

  override def save(profile: BasicProfile, mode: SaveMode): Future[BasicUser] = Future successful {
    logger.debug("SaveMode: " + mode)

    mode match {
      case SaveMode.SignUp =>
        DB withTransaction { implicit session =>
          val oAuth1InfoId = profile.oAuth1Info.map(o1 =>
            (oauth1s returning oauth1s.map(_.id)) += OAuth1(None, o1.token, o1.secret)
          )
          val oAuth2InfoId = profile.oAuth2Info.map(o2 =>
            (oauth2s returning oauth2s.map(_.id)) += OAuth2(None, o2.accessToken, o2.tokenType, o2.expiresIn, o2.refreshToken)
          )
          val passwordInfoId = profile.passwordInfo.map(p => {
            (passwords returning passwords.map(_.id)) += Password(None, p.hasher, p.password, p.salt)
          })
          val profileId = (profiles returning profiles.map(_.id)) += Profile(
            None,
            profile.providerId,
            profile.userId,
            profile.firstName,
            profile.lastName,
            profile.fullName,
            profile.email,
            profile.avatarUrl,
            profile.authMethod.method,
            oAuth1InfoId,
            oAuth2InfoId,
            passwordInfoId
          )

          users += User(profile.userId, profileId)

          BasicUser(profile, List())
        }
      case SaveMode.LoggedIn =>
        DB withSession { implicit session =>
          users.filter(_.id === profile.userId).firstOption.get.basicUser
        }
      case _ => null
    }
  }

  override def deleteExpiredTokens(): Unit = {
    DB withSession { implicit session =>
      mailTokens.filter(_.expirationTime < DateTime.now()).delete
      ()
    }
  }

  override def updatePasswordInfo(user: BasicUser, info: PasswordInfo): Future[Option[BasicProfile]] = Future successful {
    val userId = user.main.userId

    DB withSession { implicit session =>
      passwords
        .filter(_.userId === userId)
        .update(Password(None, info.hasher, info.password, info.salt))

        profiles
          .filter(p => p.userId === userId && p.providerId === UsernamePasswordProvider.UsernamePassword)
          .firstOption.map(p => p.basicProfile)
    }
  }

  override def findToken(uuid: String): Future[Option[MailToken]] = Future successful {
    DB withSession { implicit session =>
      mailTokens.filter(_.uuid === uuid).firstOption
    }
  }

  override def saveToken(mailToken: MailToken): Future[MailToken] = Future successful {
    DB withSession { implicit session =>
      mailTokens += mailToken
    }
    mailToken
  }
}
