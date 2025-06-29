/**
 * AuthManager
 * 
 * This module aims to abstract login procedures. Results from Mojang's REST api
 * are retrieved through our Mojang module. These results are processed and stored,
 * if applicable, in the config using the ConfigManager. All login procedures should
 * be made through this module.
 * 
 * @module authmanager
 */
// Requirements
const ConfigManager          = require('./configmanager')
const { LoggerUtil }         = require('helios-core')
const { RestResponseStatus } = require('helios-core/common')
const { MojangRestAPI, MojangErrorCode } = require('helios-core/mojang')
const { MicrosoftAuth, MicrosoftErrorCode } = require('helios-core/microsoft')
const { AZURE_CLIENT_ID }    = require('./ipcconstants')
const Lang = require('./langloader')

const log = LoggerUtil.getLogger('AuthManager')

// Error messages

function microsoftErrorDisplayable(errorCode) {
    switch (errorCode) {
        case MicrosoftErrorCode.NO_PROFILE:
            return {
                title: Lang.queryJS('auth.microsoft.error.noProfileTitle'),
                desc: Lang.queryJS('auth.microsoft.error.noProfileDesc')
            }
        case MicrosoftErrorCode.NO_XBOX_ACCOUNT:
            return {
                title: Lang.queryJS('auth.microsoft.error.noXboxAccountTitle'),
                desc: Lang.queryJS('auth.microsoft.error.noXboxAccountDesc')
            }
        case MicrosoftErrorCode.XBL_BANNED:
            return {
                title: Lang.queryJS('auth.microsoft.error.xblBannedTitle'),
                desc: Lang.queryJS('auth.microsoft.error.xblBannedDesc')
            }
        case MicrosoftErrorCode.UNDER_18:
            return {
                title: Lang.queryJS('auth.microsoft.error.under18Title'),
                desc: Lang.queryJS('auth.microsoft.error.under18Desc')
            }
        case MicrosoftErrorCode.UNKNOWN:
            return {
                title: Lang.queryJS('auth.microsoft.error.unknownTitle'),
                desc: Lang.queryJS('auth.microsoft.error.unknownDesc')
            }
    }
}

function mojangErrorDisplayable(errorCode) {
    switch(errorCode) {
        case MojangErrorCode.ERROR_METHOD_NOT_ALLOWED:
            return {
                title: Lang.queryJS('auth.mojang.error.methodNotAllowedTitle'),
                desc: Lang.queryJS('auth.mojang.error.methodNotAllowedDesc')
            }
        case MojangErrorCode.ERROR_NOT_FOUND:
            return {
                title: Lang.queryJS('auth.mojang.error.notFoundTitle'),
                desc: Lang.queryJS('auth.mojang.error.notFoundDesc')
            }
        case MojangErrorCode.ERROR_USER_MIGRATED:
            return {
                title: Lang.queryJS('auth.mojang.error.accountMigratedTitle'),
                desc: Lang.queryJS('auth.mojang.error.accountMigratedDesc')
            }
        case MojangErrorCode.ERROR_INVALID_CREDENTIALS:
            return {
                title: Lang.queryJS('auth.mojang.error.invalidCredentialsTitle'),
                desc: Lang.queryJS('auth.mojang.error.invalidCredentialsDesc')
            }
        case MojangErrorCode.ERROR_RATELIMIT:
            return {
                title: Lang.queryJS('auth.mojang.error.tooManyAttemptsTitle'),
                desc: Lang.queryJS('auth.mojang.error.tooManyAttemptsDesc')
            }
        case MojangErrorCode.ERROR_INVALID_TOKEN:
            return {
                title: Lang.queryJS('auth.mojang.error.invalidTokenTitle'),
                desc: Lang.queryJS('auth.mojang.error.invalidTokenDesc')
            }
        case MojangErrorCode.ERROR_ACCESS_TOKEN_HAS_PROFILE:
            return {
                title: Lang.queryJS('auth.mojang.error.tokenHasProfileTitle'),
                desc: Lang.queryJS('auth.mojang.error.tokenHasProfileDesc')
            }
        case MojangErrorCode.ERROR_CREDENTIALS_MISSING:
            return {
                title: Lang.queryJS('auth.mojang.error.credentialsMissingTitle'),
                desc: Lang.queryJS('auth.mojang.error.credentialsMissingDesc')
            }
        case MojangErrorCode.ERROR_INVALID_SALT_VERSION:
            return {
                title: Lang.queryJS('auth.mojang.error.invalidSaltVersionTitle'),
                desc: Lang.queryJS('auth.mojang.error.invalidSaltVersionDesc')
            }
        case MojangErrorCode.ERROR_UNSUPPORTED_MEDIA_TYPE:
            return {
                title: Lang.queryJS('auth.mojang.error.unsupportedMediaTypeTitle'),
                desc: Lang.queryJS('auth.mojang.error.unsupportedMediaTypeDesc')
            }
        case MojangErrorCode.ERROR_GONE:
            return {
                title: Lang.queryJS('auth.mojang.error.accountGoneTitle'),
                desc: Lang.queryJS('auth.mojang.error.accountGoneDesc')
            }
        case MojangErrorCode.ERROR_UNREACHABLE:
            return {
                title: Lang.queryJS('auth.mojang.error.unreachableTitle'),
                desc: Lang.queryJS('auth.mojang.error.unreachableDesc')
            }
        case MojangErrorCode.ERROR_NOT_PAID:
            return {
                title: Lang.queryJS('auth.mojang.error.gameNotPurchasedTitle'),
                desc: Lang.queryJS('auth.mojang.error.gameNotPurchasedDesc')
            }
        case MojangErrorCode.UNKNOWN:
            return {
                title: Lang.queryJS('auth.mojang.error.unknownErrorTitle'),
                desc: Lang.queryJS('auth.mojang.error.unknownErrorDesc')
            }
        default:
            throw new Error(`Unknown error code: ${errorCode}`)
    }
}

// Functions

/**
 * Add a Mojang account. This will authenticate the given credentials with Mojang's
 * authserver. The resultant data will be stored as an auth account in the
 * configuration database.
 * 
 * @param {string} username The account username (email if migrated).
 * @param {string} password The account password.
 * @returns {Promise.<Object>} Promise which resolves the resolved authenticated account object.
 */
exports.addMojangAccount = async function(username, password) {
    try {
        const response = await MojangRestAPI.authenticate(username, password, ConfigManager.getClientToken())
        console.log(response)
        if(response.responseStatus === RestResponseStatus.SUCCESS) {

            const session = response.data
            if(session.selectedProfile != null){
                const ret = ConfigManager.addMojangAuthAccount(session.selectedProfile.id, session.accessToken, username, session.selectedProfile.name)
                if(ConfigManager.getClientToken() == null){
                    ConfigManager.setClientToken(session.clientToken)
                }
                ConfigManager.save()
                return ret
            } else {
                return Promise.reject(mojangErrorDisplayable(MojangErrorCode.ERROR_NOT_PAID))
            }

        } else {
            return Promise.reject(mojangErrorDisplayable(response.mojangErrorCode))
        }
        
    } catch (err){
        log.error(err)
        return Promise.reject(mojangErrorDisplayable(MojangErrorCode.UNKNOWN))
    }
}

const AUTH_MODE = { FULL: 0, MS_REFRESH: 1, MC_REFRESH: 2 }

/**
 * Perform the full MS Auth flow in a given mode.
 * 
 * AUTH_MODE.FULL = Full authorization for a new account.
 * AUTH_MODE.MS_REFRESH = Full refresh authorization.
 * AUTH_MODE.MC_REFRESH = Refresh of the MC token, reusing the MS token.
 * 
 * @param {string} entryCode FULL-AuthCode. MS_REFRESH=refreshToken, MC_REFRESH=accessToken
 * @param {*} authMode The auth mode.
 * @returns An object with all auth data. AccessToken object will be null when mode is MC_REFRESH.
 */
async function fullMicrosoftAuthFlow(entryCode, authMode) {
    const authModeNames = {
        [AUTH_MODE.FULL]: 'FULL',
        [AUTH_MODE.MS_REFRESH]: 'MS_REFRESH', 
        [AUTH_MODE.MC_REFRESH]: 'MC_REFRESH'
    }
    
    log.info(`Starting Microsoft auth flow`, {
        authMode: authModeNames[authMode] || authMode,
        hasEntryCode: !!entryCode,
        entryCodeLength: entryCode ? entryCode.length : 0
    })
    
    try {

        let accessTokenRaw
        let accessToken
        if(authMode !== AUTH_MODE.MC_REFRESH) {
            log.info('Getting Microsoft access token')
            const accessTokenResponse = await MicrosoftAuth.getAccessToken(entryCode, authMode === AUTH_MODE.MS_REFRESH, AZURE_CLIENT_ID)
            if(accessTokenResponse.responseStatus === RestResponseStatus.ERROR) {
                log.error('Failed to get Microsoft access token', {
                    errorCode: accessTokenResponse.microsoftErrorCode,
                    authMode: authModeNames[authMode]
                })
                return Promise.reject(microsoftErrorDisplayable(accessTokenResponse.microsoftErrorCode))
            }
            accessToken = accessTokenResponse.data
            accessTokenRaw = accessToken.access_token
            log.info('Microsoft access token obtained successfully')
        } else {
            accessTokenRaw = entryCode
            log.info('Using existing Microsoft access token for MC refresh')
        }
        
        log.info('Getting Xbox Live token')
        const xblResponse = await MicrosoftAuth.getXBLToken(accessTokenRaw)
        if(xblResponse.responseStatus === RestResponseStatus.ERROR) {
            log.error('Failed to get Xbox Live token', {
                errorCode: xblResponse.microsoftErrorCode
            })
            return Promise.reject(microsoftErrorDisplayable(xblResponse.microsoftErrorCode))
        }
        
        log.info('Getting Xbox Live Security Token')
        const xstsResonse = await MicrosoftAuth.getXSTSToken(xblResponse.data)
        if(xstsResonse.responseStatus === RestResponseStatus.ERROR) {
            log.error('Failed to get Xbox Live Security Token', {
                errorCode: xstsResonse.microsoftErrorCode
            })
            return Promise.reject(microsoftErrorDisplayable(xstsResonse.microsoftErrorCode))
        }
        
        log.info('Getting Minecraft access token')
        const mcTokenResponse = await MicrosoftAuth.getMCAccessToken(xstsResonse.data)
        if(mcTokenResponse.responseStatus === RestResponseStatus.ERROR) {
            log.error('Failed to get Minecraft access token', {
                errorCode: mcTokenResponse.microsoftErrorCode
            })
            return Promise.reject(microsoftErrorDisplayable(mcTokenResponse.microsoftErrorCode))
        }
        
        log.info('Getting Minecraft profile')
        const mcProfileResponse = await MicrosoftAuth.getMCProfile(mcTokenResponse.data.access_token)
        if(mcProfileResponse.responseStatus === RestResponseStatus.ERROR) {
            log.error('Failed to get Minecraft profile', {
                errorCode: mcProfileResponse.microsoftErrorCode
            })
            return Promise.reject(microsoftErrorDisplayable(mcProfileResponse.microsoftErrorCode))
        }
        
        log.info('Microsoft auth flow completed successfully', {
            authMode: authModeNames[authMode],
            minecraftProfile: mcProfileResponse.data.name
        })
        
        return {
            accessToken,
            accessTokenRaw,
            xbl: xblResponse.data,
            xsts: xstsResonse.data,
            mcToken: mcTokenResponse.data,
            mcProfile: mcProfileResponse.data
        }
    } catch(err) {
        log.error('Microsoft auth flow failed with exception', {
            error: err.message || err,
            stack: err.stack,
            authMode: authModeNames[authMode]
        })
        return Promise.reject(microsoftErrorDisplayable(MicrosoftErrorCode.UNKNOWN))
    }
}

/**
 * Calculate the expiry date. Advance the expiry time by 10 seconds
 * to reduce the liklihood of working with an expired token.
 * 
 * @param {number} nowMs Current time milliseconds.
 * @param {number} epiresInS Expires in (seconds)
 * @returns 
 */
function calculateExpiryDate(nowMs, epiresInS) {
    return nowMs + ((epiresInS-10)*1000)
}

/**
 * Validates Microsoft account configuration data
 * 
 * @param {Object} account The account object to validate
 * @returns {boolean} True if account data is valid
 */
function validateMicrosoftAccountConfig(account) {
    if (!account) {
        log.warn('Account object is null or undefined')
        return false
    }
    
    if (!account.microsoft) {
        log.warn('Account missing Microsoft auth data', { uuid: account.uuid })
        return false
    }
    
    const required = ['access_token', 'refresh_token', 'expires_at']
    const missing = required.filter(field => !account.microsoft[field])
    
    if (missing.length > 0) {
        log.warn('Account missing required Microsoft fields', { 
            uuid: account.uuid,
            missing: missing 
        })
        return false
    }
    
    if (!account.expiresAt) {
        log.warn('Account missing MC token expiry', { uuid: account.uuid })
        return false
    }
    
    return true
}

/**
 * Add a Microsoft account. This will pass the provided auth code to Mojang's OAuth2.0 flow.
 * The resultant data will be stored as an auth account in the configuration database.
 * 
 * @param {string} authCode The authCode obtained from microsoft.
 * @returns {Promise.<Object>} Promise which resolves the resolved authenticated account object.
 */
exports.addMicrosoftAccount = async function(authCode) {
    log.info('Adding new Microsoft account')
    
    if (!authCode) {
        log.error('Auth code is required for adding Microsoft account')
        return Promise.reject({
            title: 'Invalid Auth Code',
            desc: 'No authorization code provided'
        })
    }

    try {
        const fullAuth = await fullMicrosoftAuthFlow(authCode, AUTH_MODE.FULL)

        // Advance expiry by 10 seconds to avoid close calls.
        const now = new Date().getTime()

        const ret = ConfigManager.addMicrosoftAuthAccount(
            fullAuth.mcProfile.id,
            fullAuth.mcToken.access_token,
            fullAuth.mcProfile.name,
            calculateExpiryDate(now, fullAuth.mcToken.expires_in),
            fullAuth.accessToken.access_token,
            fullAuth.accessToken.refresh_token,
            calculateExpiryDate(now, fullAuth.accessToken.expires_in)
        )
        
        // Validate the saved account data
        if (!validateMicrosoftAccountConfig(ret)) {
            log.error('Failed to save Microsoft account properly')
            return Promise.reject({
                title: 'Account Save Failed',
                desc: 'Failed to properly save Microsoft account data'
            })
        }
        
        ConfigManager.save()
        log.info('Microsoft account added successfully', {
            uuid: ret.uuid,
            username: ret.displayName
        })

        return ret
    } catch (err) {
        log.error('Failed to add Microsoft account', {
            error: err.message || err,
            hasAuthCode: !!authCode
        })
        throw err
    }
}

/**
 * Remove a Mojang account. This will invalidate the access token associated
 * with the account and then remove it from the database.
 * 
 * @param {string} uuid The UUID of the account to be removed.
 * @returns {Promise.<void>} Promise which resolves to void when the action is complete.
 */
exports.removeMojangAccount = async function(uuid){
    try {
        const authAcc = ConfigManager.getAuthAccount(uuid)
        const response = await MojangRestAPI.invalidate(authAcc.accessToken, ConfigManager.getClientToken())
        if(response.responseStatus === RestResponseStatus.SUCCESS) {
            ConfigManager.removeAuthAccount(uuid)
            ConfigManager.save()
            return Promise.resolve()
        } else {
            log.error('Error while removing account', response.error)
            return Promise.reject(response.error)
        }
    } catch (err){
        log.error('Error while removing account', err)
        return Promise.reject(err)
    }
}

/**
 * Remove a Microsoft account. It is expected that the caller will invoke the OAuth logout
 * through the ipc renderer.
 * 
 * @param {string} uuid The UUID of the account to be removed.
 * @returns {Promise.<void>} Promise which resolves to void when the action is complete.
 */
exports.removeMicrosoftAccount = async function(uuid){
    try {
        ConfigManager.removeAuthAccount(uuid)
        ConfigManager.save()
        return Promise.resolve()
    } catch (err){
        log.error('Error while removing account', err)
        return Promise.reject(err)
    }
}

/**
 * Validate the selected account with Mojang's authserver. If the account is not valid,
 * we will attempt to refresh the access token and update that value. If that fails, a
 * new login will be required.
 * 
 * @returns {Promise.<boolean>} Promise which resolves to true if the access token is valid,
 * otherwise false.
 */
async function validateSelectedMojangAccount(){
    const current = ConfigManager.getSelectedAccount()
    const response = await MojangRestAPI.validate(current.accessToken, ConfigManager.getClientToken())

    if(response.responseStatus === RestResponseStatus.SUCCESS) {
        const isValid = response.data
        if(!isValid){
            const refreshResponse = await MojangRestAPI.refresh(current.accessToken, ConfigManager.getClientToken())
            if(refreshResponse.responseStatus === RestResponseStatus.SUCCESS) {
                const session = refreshResponse.data
                ConfigManager.updateMojangAuthAccount(current.uuid, session.accessToken)
                ConfigManager.save()
            } else {
                log.error('Error while validating selected profile:', refreshResponse.error)
                log.info('Account access token is invalid.')
                return false
            }
            log.info('Account access token validated.')
            return true
        } else {
            log.info('Account access token validated.')
            return true
        }
    }
    
}

/**
 * Validate the selected account with Microsoft's authserver. If the account is not valid,
 * we will attempt to refresh the access token and update that value. If that fails, a
 * new login will be required.
 * 
 * @returns {Promise.<boolean>} Promise which resolves to true if the access token is valid,
 * otherwise false.
 */
async function validateSelectedMicrosoftAccount(){
    const current = ConfigManager.getSelectedAccount()
    const now = new Date().getTime()
    
    // Enhanced validation: Check for required token data
    if (!current.microsoft || !current.microsoft.expires_at || !current.expiresAt) {
        log.error('Microsoft account missing required token data', {
            hasMicrosoft: !!current.microsoft,
            hasMSExpiry: !!(current.microsoft && current.microsoft.expires_at),
            hasMCExpiry: !!current.expiresAt,
            accountUuid: current.uuid
        })
        return false
    }

    if (!current.microsoft.access_token || !current.microsoft.refresh_token) {
        log.error('Microsoft account missing access or refresh token', {
            hasAccessToken: !!current.microsoft.access_token,
            hasRefreshToken: !!current.microsoft.refresh_token,
            accountUuid: current.uuid
        })
        return false
    }

    const mcExpiresAt = current.expiresAt
    const msExpiresAt = current.microsoft.expires_at
    
    // Preemptive refresh: Check if MS token expires within 24 hours
    const refreshBuffer = 24 * 60 * 60 * 1000 // 24 hours
    const msNeedsRefresh = (msExpiresAt - now) < refreshBuffer
    const mcExpired = now >= mcExpiresAt

    log.info('Token validation status', {
        mcExpired,
        msNeedsRefresh,
        mcExpiresAt: new Date(mcExpiresAt).toISOString(),
        msExpiresAt: new Date(msExpiresAt).toISOString(),
        currentTime: new Date(now).toISOString(),
        accountUuid: current.uuid
    })

    if(!mcExpired && !msNeedsRefresh) {
        log.info('All tokens valid, no refresh needed')
        return true
    }

    // MC token expired or MS token needs preemptive refresh
    const msExpired = now >= msExpiresAt

    if(msExpired || msNeedsRefresh) {
        // MS expired or needs refresh, do full refresh.
        log.info('Performing full Microsoft token refresh', {
            reason: msExpired ? 'MS token expired' : 'MS token expiring soon',
            msExpiresAt: new Date(msExpiresAt).toISOString()
        })
        try {
            const res = await fullMicrosoftAuthFlow(current.microsoft.refresh_token, AUTH_MODE.MS_REFRESH)

            ConfigManager.updateMicrosoftAuthAccount(
                current.uuid,
                res.mcToken.access_token,
                res.accessToken.access_token,
                res.accessToken.refresh_token,
                calculateExpiryDate(now, res.accessToken.expires_in),
                calculateExpiryDate(now, res.mcToken.expires_in)
            )
            ConfigManager.save()
            log.info('Microsoft token refresh successful')
            return true
        } catch(err) {
            log.error('Microsoft full token refresh failed', {
                error: err.message || err,
                errorCode: err.microsoftErrorCode,
                hasRefreshToken: !!current.microsoft.refresh_token,
                refreshTokenLength: current.microsoft.refresh_token ? current.microsoft.refresh_token.length : 0,
                accountUuid: current.uuid
            })
            return false
        }
    } else {
        // Only MC expired, use existing MS token.
        log.info('Performing Minecraft token refresh using existing MS token')
        try {
            const res = await fullMicrosoftAuthFlow(current.microsoft.access_token, AUTH_MODE.MC_REFRESH)

            ConfigManager.updateMicrosoftAuthAccount(
                current.uuid,
                res.mcToken.access_token,
                current.microsoft.access_token,
                current.microsoft.refresh_token,
                current.microsoft.expires_at,
                calculateExpiryDate(now, res.mcToken.expires_in)
            )
            ConfigManager.save()
            log.info('Minecraft token refresh successful')
            return true
        }
        catch(err) {
            log.error('Minecraft token refresh failed', {
                error: err.message || err,
                errorCode: err.microsoftErrorCode,
                hasAccessToken: !!current.microsoft.access_token,
                accessTokenLength: current.microsoft.access_token ? current.microsoft.access_token.length : 0,
                accountUuid: current.uuid
            })
            return false
        }
    }
}

/**
 * Validates all stored Microsoft accounts on startup
 * 
 * @returns {Object} Validation results with account status
 */
exports.validateStoredAccounts = function() {
    const accounts = ConfigManager.getAuthAccounts()
    const results = {
        total: accounts.length,
        valid: 0,
        invalid: 0,
        microsoftAccounts: 0,
        issues: []
    }
    
    log.info(`Validating ${accounts.length} stored accounts`)
    
    accounts.forEach(account => {
        if (account.type === 'microsoft') {
            results.microsoftAccounts++
            if (validateMicrosoftAccountConfig(account)) {
                results.valid++
            } else {
                results.invalid++
                results.issues.push({
                    uuid: account.uuid,
                    displayName: account.displayName,
                    issue: 'Invalid configuration data'
                })
            }
        } else {
            results.valid++ // Assume Mojang accounts are valid for now
        }
    })
    
    log.info('Account validation complete', {
        total: results.total,
        valid: results.valid,
        invalid: results.invalid,
        microsoftAccounts: results.microsoftAccounts,
        issueCount: results.issues.length
    })
    
    if (results.issues.length > 0) {
        log.warn('Accounts with issues found', { issues: results.issues })
    }
    
    return results
}

/**
 * Validate the selected auth account.
 * 
 * @returns {Promise.<boolean>} Promise which resolves to true if the access token is valid,
 * otherwise false.
 */
exports.validateSelected = async function(){
    const current = ConfigManager.getSelectedAccount()

    if(current.type === 'microsoft') {
        return await validateSelectedMicrosoftAccount()
    } else {
        return await validateSelectedMojangAccount()
    }
    
}
