import $ from 'jquery';
import _ from 'underscore';
import React from 'react';
import autoBind from 'react-autobind';
import reactMixin from 'react-mixin';
import Reflux from 'reflux';
import alertify from 'alertifyjs';
import stores from '../../stores';
import bem from '../../bem';
import actions from '../../actions';
import {dataInterface} from '../../dataInterface';
import {
  t,
  formatTime
} from '../../utils';
import {HOOK_LOG_STATUSES} from '../../constants';

export default class RESTServiceLogs extends React.Component {
  constructor(props){
    super(props);
    this.state = {
      hookName: null,
      isHookActive: false,
      assetUid: props.assetUid,
      hookUid: props.hookUid,
      isLoadingHook: true,
      isLoadingLogs: true,
      logs: []
    };
    autoBind(this);
  }

  componentDidMount() {
    this.listenTo(
      actions.hooks.getLogs.completed,
      this.onLogsUpdated
    );

    dataInterface.getHook(this.state.assetUid, this.state.hookUid)
      .done((data) => {
        this.setState({
          isLoadingHook: false,
          hookName: data.name,
          isHookActive: data.active
        });
      })
      .fail((data) => {
        this.setState({
          isLoadingHook: false
        });
        alertify.error(t('Could not load REST Service'));
      });

    actions.hooks.getLogs(
      this.state.assetUid,
      this.state.hookUid,
      {
        onComplete: (data) => {
          this.setState({
            isLoadingLogs: false,
            logs: data.results
          });
        },
        onFail: (data) => {
          this.setState({
            isLoadingLogs: false
          });
          alertify.error(t('Could not load REST Service logs'));
        }
      }
    );
  }

  onLogsUpdated(data) {
    this.setState({
      logs: data.results
    });
  }

  retryAll(evt) {
    const failedLogUids = [];
    this.state.logs.forEach((log) => {
      if (log.status === HOOK_LOG_STATUSES.FAILED) {
        failedLogUids.push(log.uid);
      }
    });
    this.overrideLogsStatus(failedLogUids, HOOK_LOG_STATUSES.PENDING);

    actions.hooks.retryLogs(
      this.state.assetUid,
      this.state.hookUid,
      {
        onComplete: (response) => {
          this.overrideLogsStatus(response.pending_uids, HOOK_LOG_STATUSES.PENDING);
        }
      }
    );
  }

  retryLog(log, evt) {
    // make sure to allow only retrying failed logs
    if (log.status !== HOOK_LOG_STATUSES.FAILED) {
      return;
    }

    this.overrideLogsStatus([log.uid], HOOK_LOG_STATUSES.PENDING);

    actions.hooks.retryLog(
      this.state.assetUid,
      this.state.hookUid,
      log.uid, {
        onFail: (response) => {
          if (response.responseJSON && response.responseJSON.detail) {
            this.overrideLogMessage(log.uid, response.responseJSON.detail);
          }
          this.overrideLogsStatus([log.uid], HOOK_LOG_STATUSES.FAILED);
        }
      }
    );
  }

  overrideLogMessage(logUid, newMessage) {
    const currentLogs = this.state.logs;
    currentLogs.forEach((currentLog) => {
      if (currentLog.uid === logUid) {
        currentLog.message = newMessage;
      }
    });
    this.setState({
      logs: currentLogs
    });
  }

  // useful to mark logs as pending, before BE tells about it
  // NOTE: logUids is an array
  overrideLogsStatus(logUids, newStatus) {
    const currentLogs = this.state.logs;
    currentLogs.forEach((currentLog) => {
      if (logUids.includes(currentLog.uid)) {
        currentLog.status = newStatus;
      }
    });
    this.setState({
      logs: currentLogs
    });
  }

  showLogInfo(log, evt) {
    const escapedMessage = $('<div/>').text(log.message).html();
    alertify.alert(log.uid, `<pre>${escapedMessage}</pre>`);
  }

  hasAnyFailedLogs() {
    let hasAny = false;
    this.state.logs.forEach((log) => {
      if (log.status === HOOK_LOG_STATUSES.FAILED) {
        hasAny = true;
      }
    });
    return hasAny;
  }

  /*
   * rendering methods
   */

  renderHeader() {
    return (
      <header className='rest-services-list__header'>
        <a
          className='rest-services-list__header-back-button'
          href={`/#/forms/${this.state.assetUid}/settings/rest`}
        >
          <i className='k-icon-prev' />
          {t('Services list')}
        </a>

        <h2 className='rest-services-list__header-label rest-services-list__header-right'>
          {this.state.hookName}
        </h2>
      </header>
    )
  }

  renderEmptyView() {
    return (
      <bem.FormView__cell m='rest-services-list' className='rest-services-list--empty'>
        {this.renderHeader()}

        <bem.EmptyContent>
          <bem.EmptyContent__message>
            {t('There are no logs yet')}
          </bem.EmptyContent__message>
        </bem.EmptyContent>
      </bem.FormView__cell>
    );
  }

  renderListView() {
    return (
      <bem.FormView__cell m='rest-services-list'>
        {this.renderHeader()}

        <bem.FormView__cell m={['box']}>
          <bem.ServiceRow m='header'>
            <bem.ServiceRow__column m='submission'>{t('Submission')}</bem.ServiceRow__column>
            <bem.ServiceRow__column m='status'>
              {t('Status')}
              { this.hasAnyFailedLogs() &&
                <bem.ServiceRow__actionButton
                  onClick={this.retryAll.bind(this)}
                  data-tip={t('Retry all submissions')}
                  disabled={!this.state.isHookActive}
                >
                  <i className='k-icon-replace-all'/>
                </bem.ServiceRow__actionButton>
              }
            </bem.ServiceRow__column>
            <bem.ServiceRow__column m='date'>{t('Date')}</bem.ServiceRow__column>
          </bem.ServiceRow>

          {this.state.logs.map((log, n) => {
            let statusMod = '';
            let statusLabel = '';
            if (log.status === HOOK_LOG_STATUSES.SUCCESS) {
              statusMod = 'success';
              statusLabel = t('Success');
            }
            if (log.status === HOOK_LOG_STATUSES.PENDING) {
              statusMod = 'pending';
              statusLabel = t('Pending');
            }
            if (log.status === HOOK_LOG_STATUSES.FAILED) {
              statusMod = 'failed';
              statusLabel = t('Failed');
            }

            return (
              <bem.ServiceRow key={n} >
                <bem.ServiceRow__column m='submission'>
                  {log.uid}
                </bem.ServiceRow__column>

                <bem.ServiceRow__column
                  m={['status', statusMod]}
                >
                  {statusLabel}

                  {log.status === HOOK_LOG_STATUSES.FAILED &&
                    <bem.ServiceRow__actionButton
                      disabled={!this.state.isHookActive}
                      onClick={this.retryLog.bind(this, log)}
                      data-tip={t('Retry submission')}
                    >
                      <i className='k-icon-replace' />
                    </bem.ServiceRow__actionButton>
                  }

                  {log.status === HOOK_LOG_STATUSES.FAILED && log.message.length > 0 &&
                    <bem.ServiceRow__actionButton
                      onClick={this.showLogInfo.bind(this, log)}
                      data-tip={t('More info')}
                    >
                      <i className='k-icon-information' />
                    </bem.ServiceRow__actionButton>
                  }
                </bem.ServiceRow__column>

                <bem.ServiceRow__column m='date'>
                  {formatTime(log.date_modified)}
                </bem.ServiceRow__column>
              </bem.ServiceRow>
            );
          })}
        </bem.FormView__cell>
      </bem.FormView__cell>
    );
  }

  render() {
    if (this.state.isLoadingHook || this.state.isLoadingLogs) {
      return (
        <bem.Loading>
          <bem.Loading__inner>
            <i />
            {t('loading...')}
          </bem.Loading__inner>
        </bem.Loading>
      )
    } else if (this.state.logs.length === 0) {
      return this.renderEmptyView();
    } else {
      return this.renderListView();
    }
  }
}

reactMixin(RESTServiceLogs.prototype, Reflux.ListenerMixin);
