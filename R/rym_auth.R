#' @importFrom httr2 %>%
rym_auth <-
  function(login = getOption("rym.user"), 
           new.user = FALSE, 
           token.path = getOption("rym.token_path")) {

    # check path
    if ( is.null(token.path) ) {
      
      token.path <- getwd()
      
    }
    
    # check directory
    if (!dir.exists(token.path)) {
      dir.create(token.path)
    }

    # token save

	gr_type <- "authorization_code"
	id_cl <- "ce8a59be64034bcaaa2ab190dc29b46e"
	secret_cl <- "0c658b33270245aa99b1f523d1b95c1b"
	
    if (new.user == FALSE && file.exists(paste0(paste0(token.path, "/", login, ".rymAuth.RData")))) {
      message("Load token from ", paste0(paste0(token.path, "/", login, ".rymAuth.RData")))
      load(paste0(token.path, "/", login, ".rymAuth.RData"))
      # check token expire
      if (as.numeric(difftime(token$expire_at, Sys.time(), units = "days")) < 30) {
        message("Auto refresh token")
        token_raw <- httr::POST("https://oauth.yandex.ru/token", body = list(
          grant_type = gr_type,
          refresh_token = token$refresh_token,
          client_id = id_cl,
          client_secret = secret_cl
        ), encode = "form")
        # check error
        if (!is.null(token$error_description)) {
          stop(paste0(token$error, ": ", token$error_description))
        }
        # parser
        token <- content(token_raw)
        
        # add info about expire time and login
        token$expire_at <- Sys.time() + as.numeric(token$expires_in, units = "secs")
        token$username  <- login

        # save auth token
        class(token) <- "RymToken"
        
        # save
        save(token, file = paste0(token.path, "/", login, ".rymAuth.RData"))
        message("Token rewrite in file ", paste0(token.path, "/", login, ".rymAuth.RData"))
        
        # set login
        options(rym.user = login)
        
        return(token)
      } else {
        message("Token expire in ", round(as.numeric(token$expire_at - Sys.time(), units = "days"), 0), " days")

        # set login
        options(rym.user = login)
        
        return(token)
      }
    }
    # if we dont find token file start a auth procedure
    browseURL(paste0("https://oauth.yandex.ru/authorize?response_type=code&client_id=5a87e45d5562421bb29bb9abd17321b3&redirect_uri=https://selesnow.github.io/rym/getToken/get_code.html&force_confirm=", as.integer(new.user), ifelse(is.null(login), "", paste0("&login_hint=", login))))
    # read auth code
    temp_code <- readline(prompt = "Enter authorize code:")

    # check code
    while (nchar(temp_code) != 16) {
      message("The verification code you entered is not a 16-digit code, please try entering the code again.")
      temp_code <- readline(prompt = "Enter authorize code:")
    }

    body_data <- list(
    grant_type = gr_type,
    code = temp_code,
    client_id = id_cl,
    client_secret = secret_cl)
  
	response <- request("https://oauth.yandex.ru/token") %>%
    req_body_form(!!!body_data) %>%
    req_perform()
 
	token <- resp_body_json(response)
	token$expire_at <- Sys.time() + token$expires_in
    # token class
    class(token) <- "RymToken"
    
    # add info about expire time and login
    token$username  <- login
    
    # check error
    if (!is.null(token$error_description)) {
      stop(paste0(token$error, ": ", token$error_description))
    }

    # save token in file
    message("Do you want save API credential in local file (", paste0(token.path, "/", login, ".rymAuth.RData"), "), for use it between R sessions?")
    ans <- readline("y / n (recomedation - y): ")

    if (tolower(ans) %in% c("y", "yes", "ok", "save")) {
      save(token, file = paste0(token.path, "/", login, ".rymAuth.RData"))
      message("Token saved in file ", paste0(token.path, "/", login, ".rymAuth.RData"))
    }
    
    # set login
    options(rym.user = login)
    return(token)
  }
