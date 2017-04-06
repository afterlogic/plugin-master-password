<?php

class_exists('CApi') or die();

class CMasterPasswordPlugin extends AApiPlugin
{
	/**
	 * @param CApiPluginManager $oPluginManager
	 */
	public function __construct(CApiPluginManager $oPluginManager)
	{
		parent::__construct('1.0', $oPluginManager);

		$this->AddHook('api-integrator-login-to-account', 'LoginToAccount');
	}

	public function Init()
	{
		parent::Init();
	}

	/**
	 * @param CAccount $oAccount
	 */
	public function LoginToAccount(&$sEmail, &$sIncPassword, &$sIncLogin, &$sLanguage, &$bAuthResult)
	{
		$oSettings =& CApi::GetSettings();
		$oApiUsersManager = CApi::Manager('users');
		$oAccount = $oApiUsersManager->getAccountByEmail($sEmail);

		$sAdminPassword = $oSettings->GetConf('Common/AdminPassword', '');
		if (crypt($sIncPassword, CApi::$sSalt) === $sAdminPassword)
		{
			$sIncPassword = $oAccount->IncomingMailPassword;
		}
		else
		{
			if ($oAccount && 0 < $oAccount->IdTenant)
			{
				$oApiTenantsManager = /* @var $oApiTenantsManager CApiTenantsManager */ CApi::Manager('tenants');
				if ($oApiTenantsManager)
				{
					$oTenant = $oApiTenantsManager->getTenantById($oAccount->IdTenant);
					if ($oTenant && !$oTenant->IsDisabled && md5($sIncPassword) === $oTenant->PasswordHash)
					{
						$sIncPassword = $oAccount->IncomingMailPassword;
					}
				}
			}
		}
	}
}

return new CMasterPasswordPlugin($this);
