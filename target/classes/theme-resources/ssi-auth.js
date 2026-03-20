(function() {
    'use strict';

    var SSIAuth = (function() {
        var config = {
            pollInterval: 5000,
            maxAttempts: 60,
            statusEndpoint: null,
            realm: null,
            sessionId: null,
            tabId: null,
            onStatusChange: null,
            onComplete: null,
            onError: null,
            debug: false
        };

        var state = {
            pollTimer: null,
            attempts: 0,
            alreadySubmitted: false
        };

        function log(message) {
            if (config.debug) {
                console.log('[SSI Auth] ' + message);
            }
        }

        function logError(message, error) {
            console.error('[SSI Auth] ' + message, error || '');
        }

        function urlParams() {
            return new URLSearchParams(window.location.search);
        }

        function getTabId() {
            return urlParams().get('execution');
        }

        function checkStatus() {
            if (state.alreadySubmitted || state.attempts >= config.maxAttempts) {
                log('Stopping polling: ' + (state.alreadySubmitted ? 'already submitted' : 'max attempts reached'));
                stopPolling();
                if (state.attempts >= config.maxAttempts && config.onError) {
                    config.onError({ message: 'max_attempts_reached', attempts: state.attempts });
                }
                return;
            }

            state.attempts++;

            var statusUrl = config.statusEndpoint
                .replace('{realm}', config.realm)
                .replace('{sessionId}', config.sessionId)
                .replace('{tabId}', config.tabId);

            log('Checking status (attempt ' + state.attempts + '): ' + statusUrl);

            fetch(statusUrl, {
                method: 'GET',
                cache: 'no-store',
                headers: {
                    'Accept': 'application/json'
                }
            })
            .then(function(response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                return response.json();
            })
            .then(function(data) {
                log('Status response: ' + JSON.stringify(data));

                if (config.onStatusChange) {
                    config.onStatusChange(data, state.attempts);
                }

                if (data.status === 'done' || data.status === 'waiting-presentation') {
                    state.alreadySubmitted = true;
                    log('Verification complete, submitting form...');
                    stopPolling();
                    if (config.onComplete) {
                        config.onComplete(data);
                    }
                }
            })
            .catch(function(error) {
                logError('Failed to fetch status:', error);
                if (config.onError) {
                    config.onError(error);
                }
            });
        }

        function startPolling(options) {
            if (options) {
                for (var key in options) {
                    if (options.hasOwnProperty(key)) {
                        config[key] = options[key];
                    }
                }
            }

            if (!config.realm || !config.sessionId) {
                logError('Missing required config: realm or sessionId');
                return false;
            }

            config.tabId = config.tabId || getTabId();

            if (!config.tabId) {
                logError('tabId not available from URL');
                return false;
            }

            if (!config.statusEndpoint) {
                config.statusEndpoint = '/realms/{realm}/custom-resource/status?sessionId={sessionId}&tabId={tabId}';
            }

            log('Starting polling with tabId: ' + config.tabId);

            state.attempts = 0;
            state.alreadySubmitted = false;
            state.pollTimer = setInterval(checkStatus, config.pollInterval);

            checkStatus();

            return true;
        }

        function stopPolling() {
            if (state.pollTimer) {
                clearInterval(state.pollTimer);
                state.pollTimer = null;
                log('Polling stopped');
            }
        }

        function submitForm(formId) {
            var form = document.getElementById(formId);
            if (form) {
                form.submit();
            } else {
                logError('Form not found: ' + formId);
            }
        }

        function updateCounter(elementId, attempts, max) {
            var element = document.getElementById(elementId);
            if (element) {
                element.textContent = 'Polling attempt: ' + attempts + '/' + max;
            }
        }

        function updateStatus(elementId, status) {
            var element = document.getElementById(elementId);
            if (element) {
                element.textContent = status;
            }
        }

        function showError(elementId, message) {
            var element = document.getElementById(elementId);
            if (element) {
                element.textContent = message;
                element.style.display = 'block';
            }
        }

        function hideError(elementId) {
            var element = document.getElementById(elementId);
            if (element) {
                element.style.display = 'none';
            }
        }

        function showRetryButton(elementId) {
            var element = document.getElementById(elementId);
            if (element) {
                element.style.display = 'inline-block';
            }
        }

        function hideRetryButton(elementId) {
            var element = document.getElementById(elementId);
            if (element) {
                element.style.display = 'none';
            }
        }

        function setProgressStep(stepNumber) {
            var steps = document.querySelectorAll('.progress-step');
            steps.forEach(function(step, index) {
                step.classList.remove('active', 'completed');
                if (index + 1 < stepNumber) {
                    step.classList.add('completed');
                } else if (index + 1 === stepNumber) {
                    step.classList.add('active');
                }
            });
        }

        return {
            startPolling: startPolling,
            stopPolling: stopPolling,
            submitForm: submitForm,
            updateCounter: updateCounter,
            updateStatus: updateStatus,
            showError: showError,
            hideError: hideError,
            showRetryButton: showRetryButton,
            hideRetryButton: hideRetryButton,
            setProgressStep: setProgressStep,
            config: function() { return config; },
            state: function() { return state; }
        };
    })();

    window.SSIAuth = SSIAuth;

})();
