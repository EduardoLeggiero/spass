package io.spass.users.service.slick

import play.api.db.slick.DB
import securesocial.core.authenticator.{Authenticator, CookieAuthenticator, HttpHeaderAuthenticator}
import io.spass.users.models.{UserAuthenticator, UserTableQueries, BasicUser}
import UserTableQueries.{users, userAuthenticators}

import scala.concurrent.Future
import scala.reflect.ClassTag
import scala.slick.driver.JdbcDriver.simple._
import play.api.Play.current


/**
 * @author Joseph Dessens
 * @since 2014-08-25
 */
class SlickAuthenticatorStore[A <: Authenticator[BasicUser]] extends securesocial.core.authenticator.AuthenticatorStore[A] {
  /**
   * Retrieves an Authenticator from the backing store
   *
   * @param id the authenticator id
   * @param ct the class tag for the Authenticator type
   * @return an optional future Authenticator
   */
  override def find(id: String)(implicit ct: ClassTag[A]): Future[Option[A]] = Future successful {
    DB withSession { implicit session =>
      userAuthenticators.filter(_.id === id).firstOption match {
        case Some(sa) =>
          users.filter(_.id === sa.userId).firstOption match {
            case Some(sbu) =>
              val basicUser = sbu.basicUser
              ct.runtimeClass.getSimpleName match {
                case "CookieAuthenticator" =>
                  Option(
                    CookieAuthenticator(
                      sa.id,
                      basicUser,
                      sa.expirationDate,
                      sa.lastUsed,
                      sa.creationDate,
                      this.asInstanceOf[SlickAuthenticatorStore[CookieAuthenticator[BasicUser]]]
                    ).asInstanceOf[A]
                  )
                case "HttpHeaderAuthenticator" =>
                  Option(
                    HttpHeaderAuthenticator(
                      sa.id,
                      basicUser,
                      sa.expirationDate,
                      sa.lastUsed,
                      sa.creationDate,
                      this.asInstanceOf[SlickAuthenticatorStore[HttpHeaderAuthenticator[BasicUser]]]
                    ).asInstanceOf[A]
                  )
                case _ => None
              }
            case None => None
          }
        case None => None
      }
    }
  }

  /**
   * Deletes an Authenticator from the backing store
   *
   * @param id the authenticator id
   * @return a future of Unit
   */
  override def delete(id: String): Future[Unit] = Future successful {
    DB withSession { implicit session =>
      userAuthenticators.filter(_.id === id).delete
      ()
    }
  }

  /**
   * Saves/updates an authenticator in the backing store
   *
   * @param authenticator the istance to save
   * @param timeoutInSeconds the timeout. after this time has passed the backing store needs to remove the entry.
   * @return the saved authenticator
   */
  override def save(authenticator: A, timeoutInSeconds: Int): Future[A] = Future successful {
    DB withSession { implicit session =>
      userAuthenticators += UserAuthenticator(
        authenticator.id,
        authenticator.user.main.userId,
        authenticator.expirationDate,
        authenticator.lastUsed,
        authenticator.creationDate
      )
      authenticator
    }
  }
}
