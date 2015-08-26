import React from 'react/addons';
import Router from 'react-router';
import {log, t} from '../utils';
import icons from '../icons';
import stores from '../stores';
import classNames from 'classnames';
import Reflux from 'reflux';
import bem from '../bem';

var actions = require('../actions');
var assign = require('react/lib/Object.assign');

let Link = Router.Link;

class DrawerTitle extends React.Component {
  render () {
    var kls = "sidebar-title"
    if (this.props.separator) {
      kls += " separator";
    }
    return (
        <li className={kls}>
          <span>{this.props.label}</span>
        </li>
      )
  }
}
class DrawerLink extends React.Component {
  onClick (evt) {
    if (!this.props.href) {
      evt.preventDefault();
    }
    if (this.props.onClick) {
      this.props.onClick(evt);
    }
  }
  render () {
    var icon_class = "menu-icon fa fa-fw fa-"+(this.props['fa-icon'] || 'table')
    var icon = (<span className={icon_class}></span>);

    var link;
    if (this.props.linkto) {
      link = <Link to={this.props.linkto} className="mdl-navigation__link"
                    activeClassName="active">{icon} {this.props.label}</Link>
    } else {
      link = <a href={this.props.href || "#"}
      							className="mdl-navigation__link"
      							onClick={this.onClick.bind(this)}>{icon} {this.props.label}</a>
    }
    return link;
  }
}
var Drawer = React.createClass({
  mixins: [
    Reflux.connect(stores.session),
    Reflux.connect(stores.pageState),
  ],
  getInitialState () {
    return assign({
      showRecent: true
    }, stores.pageState.state);
  },
  logout () {
    actions.auth.logout();
  },
  render () {
    return (
          <div className="mdl-layout__drawer mdl-color--blue-grey-800">
            <span className="mdl-layout-title">
              <a href="/">
                <bem.AccountBox__logo />
              </a>
            </span>
            <nav className="mdl-navigation">
            	<div className="drawer-separator"></div>
              <span className="mdl-navigation__heading">{t('drafts in progress')}</span>

	            <DrawerLink label={t('forms')} linkto='forms' fa-icon="files-o" />
  	          <DrawerLink label={t('library')} linkto='library' fa-icon="book" />
    	        <DrawerLink label={t('collections')} linkto='collections' fa-icon="folder-o" />

    	        <div className="drawer-separator"></div>
    	        <span className="mdl-navigation__heading">{t('deployed projects')}</span>
	            { stores.session.currentAccount ?
    	            <DrawerLink label={t('projects')} active='true' href={stores.session.currentAccount.projects_url} fa-icon="globe" />
  	          :null }

  	          <div className="drawer-separator"></div>
  	          <span className="mdl-navigation__heading">{t('account actions')}</span>
	            { this.state.isLoggedIn ?
  	            <DrawerLink label={t('logout')} onClick={this.logout} fa-icon="sign-out" />
    	        :
      	        <DrawerLink label={t('login')} href='/api-auth/login/?next=/' fa-icon="sign-in" />
        	    }
            </nav>
          </div>
      )
  }
});

export default Drawer;
