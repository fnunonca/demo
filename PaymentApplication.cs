using Application.DTO.AppSettings;
using Application.DTO.Common;
using Application.DTO.Request.Payment;
using Application.DTO.Response;
using Application.Interface;
using Domain.Entity;
using Domain.Interface;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Transversal.Common;
using Transversal.Common.Helpers;

namespace Application.Main.Controller
{
    public class PaymentApplication: IPaymentApplication
    {
        private readonly IAppLogger _Logger;
        private readonly IConfiguration _configuration;
        private readonly ISecurityDomain _securityDomain;
        private readonly IAuthorizationDomain _authorizationDomain;
        private readonly IAuthenticationDomain _authenticationDomain;
        private readonly IAutoreversaDomain _autoreversaDomain;
        private readonly IScoringDomain _scoringDomain;
        private readonly IConfigurationDomain _entityDomain;
        private readonly ITokenizationDomain _tokenizationDomain;
        private ConfigController _config;
        private readonly IRequestValidationPaymentDomain _requestValidationDomain;
        private readonly IEncryptionDomain _encryptionDomain;
        private readonly IBinDomain _binDomain;
        private readonly IBin3dsDomain _bin3dsDomain;
        private readonly IDetokenizeDomain _detokenizeDomain;
        private readonly IHelpful _helpful;
        private readonly IAccountValidateDomain _accountValidateDomain;
        private readonly ICancelDomain _cancelDomain;
        private readonly IPaymentValidationDomain _paymentValidationDomain;
        private readonly ITransactionDomain _transactionDomain;
        public PaymentApplication(
           IAppLogger logger,
           IConfiguration configuration,
           ISecurityDomain securityDomain,
           IAuthorizationDomain authorizationDomain,
           IAuthenticationDomain authenticationDomain,
           IAutoreversaDomain autoreversaDomain,
           IScoringDomain scoringDomain,
           ITokenizationDomain tokenizationDomain,
           IOptionsSnapshot<ConfigController> configController,
           IRequestValidationPaymentDomain requestValidationDomain,
           IEncryptionDomain encryptionDomain,
           IConfigurationDomain entityDomain,
           IBinDomain binDomain,
           IBin3dsDomain bin3DsDomain,
           IDetokenizeDomain detokenizeDomain,
           IHelpful helpful,
           IAccountValidateDomain accountValidateDomain,
           ICancelDomain cancelDomain,
           IPaymentValidationDomain paymentValidationDomain,
           ITransactionDomain transactionDomain)
        {
            _Logger = logger;
            _configuration = configuration;
            _securityDomain = securityDomain;
            _scoringDomain = scoringDomain;
            _tokenizationDomain = tokenizationDomain;
            _authorizationDomain = authorizationDomain;
            _authenticationDomain = authenticationDomain;
            _autoreversaDomain = autoreversaDomain;
            _config = configController.Value;
            _requestValidationDomain = requestValidationDomain;
            _encryptionDomain = encryptionDomain;
            _entityDomain = entityDomain;
            _binDomain = binDomain;
            _bin3dsDomain = bin3DsDomain;
            _detokenizeDomain = detokenizeDomain;
            _helpful = helpful;
            _accountValidateDomain = accountValidateDomain;
            _cancelDomain = cancelDomain;
            _paymentValidationDomain = paymentValidationDomain;
            _transactionDomain = transactionDomain;
        }

        public async Task<ResponsePaymentDto> Payment(
            RequestPaymentDto request, 
            string token, string transactionId, ServerDto serverDto)
        {
            ResponsePaymentDto response = new ResponsePaymentDto();
            bool haveScoring = false;
            bool haveAuthentication = false;
            bool haveBinValidate = true;
            int? flowType = 0;
            try
            {
                DateTime dateNow = DateTime.Now;
                response.Response = new ResponsePaymentBody();
                response.Response.CodeAuth = "";
                string dateTransaction = dateNow.ToString("yyyyMMdd");
                string timeTransaction = dateNow.ToString("HHmmss");

                //Si es segunda interaccion que no ingrese a scoring ni validate bin
                if (await _authenticationDomain.IsPosteriorInteracion(request))
                {
                    haveScoring = false;
                    haveBinValidate = false;

                }
                await _helpful.WriteToken(token, transactionId, Constants.Payment);

                var validationPayment = await _paymentValidationDomain
                    .Validate(request, token , transactionId, haveBinValidate);

                if (!validationPayment.Code.Equals(Constants.SuccessfulCode)) return validationPayment;

                //04.- Extraer el token
                string _token = token.Replace(Constants.Bearer, string.Empty);

                //06.- Extraer el codigo de comercio del request

                string merchantCode = await _helpful.GetClaimToken(_token, "MerchantCode");
                //10.- get configuration
                #region Get Config
                var resultConfig = await _entityDomain.GetConfiguration(merchantCode, transactionId, Constants.Payment);

                //10.1 destokenizar si es pay_token
                if (request.Config.Action.ToUpper().Equals(Constants.Action.pay_token))
                {
                    List<RestClient.HeaderRest> headers = new List<RestClient.HeaderRest>();
                    headers.Add(new RestClient.HeaderRest { Name = Constants.TransactionId, Value = transactionId });
                    DetokenizeDto detokenizeDto = new DetokenizeDto();
                    detokenizeDto.CardToken = request.Config.Token.CardToken;
                    detokenizeDto.BuyerToken = request.Config.Token.BuyerToken;
                    detokenizeDto.UserId = request.Config.Order.MerchantBuyerId;
                    detokenizeDto.MethodOrigin = "Payment";
                    var detokenize = await _detokenizeDomain.Detokenize(detokenizeDto, token, headers, merchantCode, serverDto);
                    if (detokenize != null)
                    {
                        if (detokenize.Validate)
                        {
                            request.Config.Card.ExpirationMonth = detokenize.ExpirationDate.Substring(0,2);
                            request.Config.Card.ExpirationYear = detokenize.ExpirationDate.Substring(2, 2);
                            request.Config.Card.Pan = detokenize.CardNumber;
                            request.Config.Card.Brand = detokenize.Brand;

                        }
                        else
                        {
                            return await BuildResponse(detokenize.Code, detokenize.Message, 403);
                        }
                    }
                }

                //10.2 GetConfigEcommer
                haveScoring = await GetPermissionScoring(resultConfig.Brands, request.Config.Card.Brand);
                haveAuthentication = await GetPermissionAuthentication(resultConfig.Brands, request.Config.Card.Brand);
                flowType = await GetFlowType(resultConfig.Brands, request.Config.Card.Brand);

                //10.3 FlowType si es 2 consume bin3dsValidate
                if (flowType == 2)
                {
                    string bin3dsDomain = await _bin3dsDomain.Validate(request);
                    if (bin3dsDomain.ToUpper().Equals(Constants.OK))
                    {
                        haveScoring = false;
                    }
                }

                response.StatusCode = 200;
                response.Message = Constants.OK;
                response.Code = "00";
                #endregion

                //11.- Validar moneda y tipo de proceso
                #region Validations #2
                var configValidation = await _paymentValidationDomain.ConfigValidate(request, resultConfig);
                if (!configValidation.Code.Equals(Constants.SuccessfulCode)) return configValidation;
                #endregion

                #region Action Register
                if (request.Config.Action.ToUpper().Equals(Constants.Action.register))
                {
                    //Get monto para validar
                    double amountValidate = await GetAmountValidate(request, resultConfig);
                    string _amountValidate = await FormatAmount(amountValidate);

                    //validacion de cuenta solo es para MC y Visa
                    bool disabledAccountValidate = false;
                    disabledAccountValidate = await IsDisabledAccountValidate(request.Config.Card.Brand.ToUpper());

                    if (amountValidate > 0 || disabledAccountValidate)
                    {
                        ValidationScoring scoringValidate = new ValidationScoring();
                        scoringValidate.Idrpta = string.Empty;
                        scoringValidate.Message = string.Empty;
                        scoringValidate.Status = string.Empty;

                        AuthorizationValidateDto authorizationValidateDto = new AuthorizationValidateDto();
                        authorizationValidateDto.AmountValidate = _amountValidate;
                        authorizationValidateDto.TransactionId = transactionId;
                        authorizationValidateDto.MerchantCode = merchantCode;
                        authorizationValidateDto.ValidateAccount = true;
                        authorizationValidateDto.idLogMpi = 0;
                        authorizationValidateDto.Provider = "3";
                        authorizationValidateDto.ValueAthentication = "";

                        var authorizationValidation = await _authorizationDomain
                            .Authorize(request, scoringValidate, resultConfig.Configuration, authorizationValidateDto, serverDto);

                        if (authorizationValidation.Validate)
                        {
                            //escribir datos de salida
                            var x = await _transactionDomain
                                .UpdateTransaction(authorizationValidation.TransactionIDPayment, DateTime.Now.ToString(Constants.DateTimeFormats.yyyyMMddHHmmssfff));


                            //Aplicar Cancel
                            CancelValidationDto cancelValidationDto = new CancelValidationDto();
                            cancelValidationDto.TransactionId = transactionId;
                            cancelValidationDto.MerchantCode = merchantCode;
                            cancelValidationDto.UniqueId = authorizationValidation.UniqueId;
                            cancelValidationDto.AuthorizationCode = authorizationValidation.AuthorizationCode;
                            cancelValidationDto.AmountValidate = authorizationValidateDto.AmountValidate;

                            var cancel = await _cancelDomain.Cancel(request, cancelValidationDto, serverDto, token);
                        }
                        else
                        {
                            return await BuildResponse(authorizationValidation.Code, authorizationValidation.Message, 403);
                        }
                        
                    }
                    else
                    {
                        var accountValidate = await _accountValidateDomain
                            .ValidateAccount(request, token, merchantCode, transactionId, serverDto, _amountValidate);

                        if (!accountValidate.Validate) return await BuildResponse(accountValidate.Code, accountValidate.MessageFriendly, 403);
                    }

                    //se reemplaza el monto a tokenizar
                    string ammountRequest = request.Config.Order.Amount;
                    request.Config.Order.Amount = _amountValidate;

                    var tokenization = await _tokenizationDomain.Tokenize(request, token, merchantCode, transactionId, serverDto);
                    ResponsePaymentDto responseTokenize = new ResponsePaymentDto();
                    responseTokenize.Code = tokenization.Code;
                    responseTokenize.Message = tokenization.Message;
                    responseTokenize.StatusCode = tokenization.Code.Equals("00") ? 200 : 403;
                    responseTokenize.Response = new ResponsePaymentBody();
                    
                    if (tokenization.Validate)
                    {
                        responseTokenize.Response.Tokenization = new TokenizationResponsePaymentDto();
                        responseTokenize.Response.Tokenization.CardToken = tokenization.CardToken;
                        responseTokenize.Response.Tokenization.BuyerToken = tokenization.BuyerToken;
                    }

                    responseTokenize.Response.Amount = request.Config.Order.Amount;
                    responseTokenize.Response.Currency = request.Config.Order.Currency;
                    responseTokenize.Response.OrderNumber = request.Config.Order.OrderNumber;
                    responseTokenize.Response.DateTransaction = dateTransaction;
                    responseTokenize.Response.TimeTransaction = timeTransaction;

                    //se retorna el valor del monto en caso se haya cambiado por la validacion de cuenta
                    request.Config.Order.Amount = ammountRequest;
                    return responseTokenize;
                }
                #endregion

                //#region Action Pay_Register
                //if (request.Config.Action.ToUpper().Equals(Constants.Action.pay_register))
                //12.- consumo Scoring
                //si el action es register no va a scoring ni autorizacion
                ValidationScoring scoring = new ValidationScoring();
                scoring.Idrpta = string.Empty;
                scoring.Message = string.Empty;
                scoring.Status = string.Empty;

                if (haveScoring)
                {
                    scoring = await _scoringDomain.Validate(request, merchantCode, transactionId);
                    if (!scoring.Validate)
                    {
                        return await _helpful
                            .BuildResponsePayment(scoring.Code, new Message { 
                                MessageUserENG = scoring.MessageUserEng, 
                                MessageENG = scoring.MessageUserEng,
                                MessageESP = scoring.MessageUser}, 403);
                        //return await BuildResponse(scoring.Code, scoring.Message, 403);
                    } 

                    //si es Review y tiene authentication el flag sigue en true
                    //si no tiene authentication retorna rechazado
                    if (scoring.Code.Equals("RW") && !haveAuthentication)
                    {
                        return await _helpful
                           .BuildResponsePayment("S01", new Message
                           {
                               MessageUserENG = "Rejected by Scoring.",
                               MessageENG = "Rejected by Api Scoring",
                               MessageESP = "Rechazado por Scoring."
                           }, 403);
                    }

                }

                //13.- Autenticacion
                int idLogMpi = 0;
                string valueAuthentication = string.Empty;

                if (haveAuthentication)
                {
                    var authentication = await _authenticationDomain.Authenticate(request, resultConfig, merchantCode, transactionId);
                    idLogMpi = authentication.IdLogMPI;
                    valueAuthentication = authentication.Value;

                    if (authentication.RequiresAdditionalRequest)
                    {
                        return new ResponsePaymentDto
                        {
                            Code = "RA2",
                            Message = "Requires additional request",
                            StatusCode = 403,
                            Response = new ResponsePaymentBody
                            {
                                Answer = authentication.Answer,
                                IdLogMPI = authentication.IdLogMPI
                            }
                        };
                    }
                    if (!authentication.Validate) return await BuildResponse(authentication.Code, authentication.Message, 403);
                }

                //14.- Autorizacion -> api bussines
                AuthorizationValidateDto authorizationDto = new AuthorizationValidateDto();
                authorizationDto.AmountValidate = string.Empty;
                authorizationDto.TransactionId = transactionId;
                authorizationDto.MerchantCode = merchantCode;
                authorizationDto.ValidateAccount = false;
                authorizationDto.idLogMpi = idLogMpi;
                authorizationDto.ValueAthentication = valueAuthentication;
                authorizationDto.Provider = "3";

                var authorization = await _authorizationDomain
                    .Authorize(request, scoring, resultConfig.Configuration, authorizationDto, serverDto);

                string amount = await _helpful.GetClaimToken(_token, Constants.Amount);
                string orderNumber = await _helpful.GetClaimToken(_token, Constants.OrderNumber);

                //15.- si falla hacer rollback --> api autoreversa
                if (authorization.Code.Equals(Constants.Reversar))
                {
                    var reversa = await _autoreversaDomain
                        .Reversa(merchantCode, orderNumber, amount, response.Response.Currency);
                }

                if (authorization.Code.Equals(Constants.SuccessfulCode))
                {
                    response.Response.CodeAuth = authorization.AuthorizationCode;
                    response.Response.NumberReference = authorization.ReferenceNumber;
                    response.Response.UniqueId = authorization.UniqueId;
                    response.MessageUserEng = authorization.MessageUserEng;
                    response.MessageUser = authorization.MessageUser;

                    if (request.Config.Action.ToUpper().Equals(Constants.Action.pay_register) && request.Config.Card.Save)
                    {
                        var resultTokenization = await _tokenizationDomain.Tokenize(request, token, merchantCode, transactionId, serverDto);
                        if (resultTokenization.Validate)
                        {
                            response.Response.Tokenization = new TokenizationResponsePaymentDto();
                            response.Response.Tokenization.BuyerToken = resultTokenization.BuyerToken;
                            response.Response.Tokenization.CardToken = resultTokenization.CardToken;
                        }
                    }

                    //escribir datos de salida
                    var x = await _transactionDomain
                        .UpdateTransaction(authorization.TransactionIDPayment, DateTime.Now.ToString(Constants.DateTimeFormats.yyyyMMddHHmmssfff));

                }
                else
                {
                    response.Code = authorization.Code;
                    response.Message = authorization.Message;
                    response.MessageUserEng = authorization.MessageUserEng;
                    response.MessageUser = authorization.MessageUser;
                }

                response.Response.Amount = request.Config.Order.Amount;
                response.Response.Currency = request.Config.Order.Currency;
                response.Response.OrderNumber = request.Config.Order.OrderNumber;
                response.Response.DateTransaction = dateTransaction;
                response.Response.TimeTransaction = timeTransaction;
                response.Response.Signature = await _encryptionDomain.Signature(request, request.Config.MerchantCode);

                return await Task.Run(() => response);

            }
            catch (Exception e)
            {
                _Logger.LogError(e, $"{transactionId }|Payment|Exception");
                return await _helpful.BuildResponsePaymentErrorInternal();
            }
            
        }

        #region Private Methods


        private async Task<bool> IsDisabledAccountValidate(string brand)
        {
            bool accountValidate = true;
            if (brand.Equals("MC")) accountValidate = false;
            if (brand.Equals("VS")) accountValidate = false;

            return await Task.Run(() => accountValidate);
        }
        private async Task<ResponsePaymentDto> BuildResponse(string code, string message, int statusCode)
        {
            return await Task.Run(() => new ResponsePaymentDto { Code = code, Message = message, StatusCode = statusCode});
        }

        private async Task<string> FormatAmount(double amountValidate)
        {
            string amount = string.Empty;

            amount = amountValidate.ToString("0.00");

            return await Task.Run(() => amount);
        }

        private async Task<double> GetAmountValidate(RequestPaymentDto request, ConfigurationDto resultConfig)
        {
            double amount = 0;

            resultConfig.Brands?.ForEach(x =>
            {
                if (x.Code.ToUpper().Equals(request.Config.Card.Brand.ToUpper()))
                {
                    amount = x.TokenizationAmount;
                }
            });

            return await Task.Run(() => amount);
        }

        private async Task<bool> GetPermissionAuthentication(List<Brand> brands, string brand)
        {
            bool permission = false;
            brands?.ForEach(x => {
                if (x.Code.ToUpper().Equals(brand.ToUpper()))
                {
                    permission = x.FlagAuthentication == "1" ? true : false;
                }
            });

            return await Task.Run(() => permission);
        }

        private async Task<bool> GetPermissionScoring(List<Brand> brands, string brand)
        {
            bool permission = false;
            brands?.ForEach(x => {
                if (x.Code.ToUpper().Equals(brand.ToUpper()))
                {
                    permission = x.FlagScoring == 1 ? true : false;
                }
            });

            return await Task.Run(() => permission);
        }
        private async Task<int?> GetFlowType(List<Brand> brands, string brand)
        {
            int? flowType = 0;
            brands?.ForEach(x => {
                if (x.Code.ToUpper().Equals(brand.ToUpper()))
                {
                    flowType = x.FlowType;
                }
            });

            return await Task.Run(() => flowType);
        }
        #endregion
    }
}
