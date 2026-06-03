<?php

namespace Apps\Tms\Components\Auth;

use System\Base\BaseComponent;

class AuthComponent extends BaseComponent
{
    public function viewAction()
    {
        $this->view->setLayout('auth');

        $this->view->canRegister = false;

        $this->view->canRecoverPassword = false;

        if ($this->app['registration_allowed'] && $this->app['registration_allowed'] == '1') {
            $this->view->canRegister = true;
        }
        if ($this->app['recover_password'] && $this->app['recover_password'] == '1') {
            $this->view->canRecoverPassword = true;
        }

        if (isset($this->session->needAgentAuth) && $this->session->needAgentAuth === true) {

            $this->setNeedAuthHeader();

            $this->view->pick('auth/agent');

            $this->session->needAgentAuth = false;

            return;
        }

        $domain = $this->domains->getDomain();

        if ($this->access->auth->check()) {
            if (isset($domain['exclusive_to_default_app']) &&
                $domain['exclusive_to_default_app'] == 1
            ) {
                return $this->response->redirect('/');
            } else {
                return $this->response->redirect('/' . strtolower($this->app['route']));
            }
        }

        if (isset($this->getData()['pwreset']) && $this->getData()['pwreset'] === 'true') {
            $this->view->coreSettings = $this->core->core['settings'];

            $this->view->canUse2fa = $this->access->auth->twoFa->canUse2fa();

            $this->view->pick('auth/pwreset');

            return;
        } else if (isset($this->getData()['forgot']) && $this->getData()['forgot'] === 'password') {
            if ($this->app['recover_password'] == '0' || !$this->app['recover_password']) {
                $this->response->setStatusCode(404);

                return $this->response->send();

                exit;
            }

            $this->view->pick('auth/forgot');

            return;
        } else if (isset($this->getData()['setup2fa']) && $this->getData()['setup2fa'] === 'true') {

            $this->view->pick('auth/setup2fa');

            return;
        }

        $this->setNeedAuthHeader();

        if ($this->request->isAjax()) {
            $this->view->disable();
        }
    }

    protected function setNeedAuthHeader()
    {
        $this->response->setHeader('NEED_AUTH', '1');
        $this->response->setHeader('REDIRECT_URL', '/' . strtolower($this->app['route'] . '/auth'));
    }

    public function loginAction()
    {
        $this->requestIsPost();

        $auth = $this->access->auth->login($this->postData());

        $this->addResponse(
            $this->access->auth->packagesData->responseMessage,
            $this->access->auth->packagesData->responseCode,
            $this->access->auth->packagesData->responseData ?? []
        );

        if ($auth) {
            $this->view->redirectUrl = $this->access->auth->packagesData->redirectUrl;
        }
    }

    public function logoutAction()
    {
        if ($this->access->auth->logout()) {
            $this->view->redirectUrl = $this->access->auth->packagesData->redirectUrl;

            $this->addResponse('Ok');

            return true;
        }

        $this->addResponse('Error Logging out!', 1);
    }

    public function forgotAction()
    {
        $this->requestIsPost();

        $this->access->auth->password->forgotPassword($this->postData());

        $this->addResponse(
            $this->access->auth->password->packagesData->responseMessage,
            $this->access->auth->password->packagesData->responseCode
        );
    }

    public function pwresetAction()
    {
        $this->requestIsPost();

        $this->access->auth->password->resetPassword($this->postData());

        $this->view->responseMessage = $this->access->auth->password->packagesData->responseMessage;
        $this->view->responseCode = $this->access->auth->password->packagesData->responseCode;

        if (isset($this->access->auth->password->packagesData->redirectUrl)) {
            $this->view->redirectUrl = $this->access->auth->password->packagesData->redirectUrl;
        }
        if (isset($this->access->auth->password->packagesData->responseData)) {
            $this->view->responseData = $this->access->auth->password->packagesData->responseData;
        }
    }

    public function sendVerificationAction()
    {
        $this->requestIsPost();

        $this->access->agent->sendVerificationEmail();

        $this->addResponse(
            $this->access->agent->packagesData->responseMessage,
            $this->access->agent->packagesData->responseCode,
            $this->access->agent->packagesData->responseData ?? []
        );
    }

    public function verifyAction()
    {
        $this->requestIsPost();

        $this->access->agent->verifyVerficationCode($this->postData());

        $this->addResponse(
            $this->access->agent->packagesData->responseMessage,
            $this->access->agent->packagesData->responseCode
        );
    }

    public function sendTwoFaEmailAction()
    {
        $this->requestIsPost();

        $this->access->auth->twoFa->sendTwoFaEmail($this->postData());

        $this->addResponse(
            $this->access->auth->twoFa->packagesData->responseMessage,
            $this->access->auth->twoFa->packagesData->responseCode,
            $this->access->auth->twoFa->packagesData->responseData ?? []
        );
    }

    public function checkPwHibpAction()
    {
        $this->requestIsPost();

        if ($this->basepackages->utils->checkPwHibp($this->postData()['pass']) !== false) {
            $this->view->responseData = $this->basepackages->utils->packagesData->responseData;
        }

        $this->addResponse(
            $this->basepackages->utils->packagesData->responseMessage,
            $this->basepackages->utils->packagesData->responseCode
        );
    }

    public function checkPwStrengthAction()
    {
        $this->requestIsPost();

        if ($this->basepackages->utils->checkPwStrength($this->postData()['pass']) !== false) {
            $this->view->responseData = $this->basepackages->utils->packagesData->responseData;
        }

        $this->addResponse(
            $this->basepackages->utils->packagesData->responseMessage,
            $this->basepackages->utils->packagesData->responseCode
        );
    }

    public function generatePwAction()
    {
        $this->requestIsPost();

        $this->basepackages->utils->generateNewPassword($this->postData());

        $this->addResponse(
            $this->basepackages->utils->packagesData->responseMessage,
            $this->basepackages->utils->packagesData->responseCode,
            $this->basepackages->utils->packagesData->responseData
        );
    }

    public function enableTwoFaOtpAction()
    {
        $this->requestIsPost();

        if ($this->access->auth->twoFa->enableTwoFaOtp($this->postData())) {
            $this->view->provisionUrl = $this->access->auth->twoFa->packagesData->provisionUrl;

            $this->view->qrcode = $this->access->auth->twoFa->packagesData->qrcode;

            $this->view->secret = $this->access->auth->twoFa->packagesData->secret;

            $this->view->responseMessage = $this->access->auth->twoFa->packagesData->responseMessage;
        } else {
            $this->view->responseMessage = $this->access->auth->twoFa->packagesData->responseMessage;
        }

        $this->view->responseCode = $this->access->auth->twoFa->packagesData->responseCode;
    }

    public function verifyTwoFaOtpAction()
    {
        $this->requestIsPost();

        if ($this->access->auth->twoFa->verifyTwoFaOtp($this->postData())) {
            $this->view->redirectUrl = $this->links->url('/');
        }

        $this->addResponse(
            $this->access->auth->twoFa->packagesData->responseMessage,
            $this->access->auth->twoFa->packagesData->responseCode
        );
    }
}
