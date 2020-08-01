package edu.uci.ics.chakkl.service.idm.resources;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.uci.ics.chakkl.service.idm.IDMService;
import edu.uci.ics.chakkl.service.idm.logger.ServiceLogger;
import edu.uci.ics.chakkl.service.idm.models.*;
import edu.uci.ics.chakkl.service.idm.security.Crypto;
import edu.uci.ics.chakkl.service.idm.security.Session;
import edu.uci.ics.chakkl.service.idm.util.Result;
import edu.uci.ics.chakkl.service.idm.util.Util;
import javafx.util.Pair;
import org.apache.commons.codec.binary.Hex;
import org.simplejavamail.api.email.Email;
import org.simplejavamail.email.EmailBuilder;
import org.simplejavamail.mailer.MailerBuilder;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.sql.*;

@Path("/")
public class IdmEndpoint {

    @Path("register")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response register(@Context HttpHeaders headers, String jsonText)
    {
        RegisterLoginRequestModel requestModel;
        ObjectMapper mapper = new ObjectMapper();
        ServiceLogger.LOGGER.info("Register request received.");
        try
        {
            requestModel = mapper.readValue(jsonText, RegisterLoginRequestModel.class);
        }
        catch (JsonParseException e)
        {
            ServiceLogger.LOGGER.info("JSON parse error.");
            return new BaseResponseModel(Result.JSON_PARSE_ERROR).buildResponse();
        }
        catch (JsonMappingException e)
        {
            ServiceLogger.LOGGER.info("JSON mapping error.");
            return new BaseResponseModel(Result.JSON_MAPPING_ERROR).buildResponse();
        }
        catch (Exception e)
        {
            ServiceLogger.LOGGER.info("Unknown error has occurred.");
            return Util.internal_server_error();
        }
        ServiceLogger.LOGGER.info("Received email: " + requestModel.getEmail());
        switch (validatePassword(requestModel.getPassword()))
        {
            case -1:
                ServiceLogger.LOGGER.info("Password has invalid length.");
                return new BaseResponseModel(Result.PASSWORD_INVALID_LENGTH).buildResponse();
            case 1:
                ServiceLogger.LOGGER.info("Password does not meet length requirements.");
                return new BaseResponseModel(Result.PASSWORD_LENGTH_REQUIREMENT).buildResponse();
            case 2:
                ServiceLogger.LOGGER.info("Password does not meet character requirements.");
                return new BaseResponseModel(Result.PASSWORD_CHARACTER_REQUIREMENT).buildResponse();
        }
        switch (validateEmail(requestModel.getEmail()))
        {
            case 1:
                ServiceLogger.LOGGER.info("Email address has invalid length.");
                return new BaseResponseModel(Result.EMAIL_INVALID_LENGTH).buildResponse();
            case 2:
                ServiceLogger.LOGGER.info("Email address has invalid format.");
                return new BaseResponseModel(Result.EMAIL_INVALID_FORMAT).buildResponse();
        }
        ServiceLogger.LOGGER.info("Email and password has correct length and format, salt and hashing password.");
        byte salt[] = Crypto.genSalt();
        char pw[] = requestModel.getPassword();
        byte hashedPW[] = Crypto.hashPassword(pw, salt, Crypto.ITERATIONS, Crypto.KEY_LENGTH);
        String encodedSalt = Hex.encodeHexString(salt), encodedPW = Hex.encodeHexString(hashedPW);
        ServiceLogger.LOGGER.info("Finished hashing password.");
        try {
            PreparedStatement ps = IDMService.getCon().prepareStatement("INSERT INTO user (email, status, plevel, salt, pword) VALUES (?, ?, ?, ?, ?)");
            ps.setString(1, requestModel.getEmail());
            ps.setInt(2, 1);
            ps.setInt(3, 5);
            ps.setString(4, encodedSalt);
            ps.setString(5, encodedPW);
            ps.executeUpdate();
        }
        catch (SQLException e) {
            ServiceLogger.LOGGER.info("Error inserting user.");
            return new BaseResponseModel(Result.EMAIL_ALREADY_IN_USE).buildResponse();
        }
        return new BaseResponseModel(Result.REGISTER_SUCCESSFUL).buildResponse();
    }

    @Path("login")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response login(@Context HttpHeaders headers, String jsonText)
    {
        RegisterLoginRequestModel requestModel;
        ObjectMapper mapper = new ObjectMapper();
        ServiceLogger.LOGGER.info("Login request received.");
        try
        {
            requestModel = mapper.readValue(jsonText, RegisterLoginRequestModel.class);
        }
        catch (JsonParseException e)
        {
            ServiceLogger.LOGGER.info("JSON parse error.");
            return new LoginSessionResponseModel(Result.JSON_PARSE_ERROR, null).buildResponse();
        }
        catch (JsonMappingException e)
        {
            ServiceLogger.LOGGER.info("JSON mapping error.");
            return new LoginSessionResponseModel(Result.JSON_MAPPING_ERROR, null).buildResponse();
        }
        catch (Exception e)
        {
            ServiceLogger.LOGGER.info("Unknown error has occurred.");
            return Util.internal_server_error();
        }
        switch (validatePassword(requestModel.getPassword()))
        {
            case -1:
                ServiceLogger.LOGGER.info("Password has invalid length.");
                return new LoginSessionResponseModel(Result.PASSWORD_INVALID_LENGTH, null).buildResponse();
        }
        ServiceLogger.LOGGER.info("Logging in: " + requestModel.getEmail());
        switch (validateEmail(requestModel.getEmail()))
        {
            case 1:
                ServiceLogger.LOGGER.info("Email address has invalid length.");
                return new LoginSessionResponseModel(Result.EMAIL_INVALID_LENGTH, null).buildResponse();
            case 2:
                ServiceLogger.LOGGER.info("Email address has invalid format.");
                return new LoginSessionResponseModel(Result.EMAIL_INVALID_FORMAT, null).buildResponse();
        }
        if(!userExist(requestModel.getEmail())) {
            ServiceLogger.LOGGER.info("User does not exist.");
            return new BaseResponseModel(Result.USER_NOT_FOUND).buildResponse();
        }
        try {
            PreparedStatement ps = IDMService.getCon().prepareStatement("SELECT salt, pword FROM user WHERE email = ?");
            ps.setString(1, requestModel.getEmail());
            ResultSet rs = ps.executeQuery();
            if(!rs.next())
            {
                ServiceLogger.LOGGER.info("Result set is empty, user does not exist.");
                return new LoginSessionResponseModel(Result.USER_NOT_FOUND, null).buildResponse();
            }
            String encodedPW = rs.getString("pword");
            byte salt[] = Hex.decodeHex(rs.getString("salt"));
            byte hashedPW[] = Crypto.hashPassword(requestModel.getPassword(), salt, Crypto.ITERATIONS, Crypto.KEY_LENGTH);
            if(encodedPW.equals(Hex.encodeHexString(hashedPW))) //PW matches
            {
                ServiceLogger.LOGGER.info("Password matches, continuing login.");
                ps = IDMService.getCon().prepareStatement("SELECT * FROM session WHERE email = ? AND status = ?");
                ps.setString(1, requestModel.getEmail());
                ps.setInt(2, 1);
                rs = ps.executeQuery();
                if(rs.isBeforeFirst()) // there are active session
                {
                    ServiceLogger.LOGGER.info("There are active sessions, revoking them.");
                    ps = IDMService.getCon().prepareStatement("UPDATE session SET status = ? WHERE session_id = ?");
                    while(rs.next())
                    {
                        ps.setInt(1, Session.REVOKED);
                        ps.setString(2, rs.getString("session_id"));
                        ps.executeUpdate();
                    }
                }
                else // there are no active session
                {
                    ServiceLogger.LOGGER.info("No active session, creating new session.");
                }
                Session session = Session.createSession(requestModel.getEmail());
                ps = IDMService.getCon().prepareStatement("INSERT INTO session VALUES (?, ?, ?, ?, ?, ?)");
                ps.setString(1, session.getSessionID().toString());
                ps.setString(2, session.getEmail());
                ps.setInt(3, Session.ACTIVE);
                ps.setTimestamp(4, session.getTimeCreated());
                ps.setTimestamp(5, session.getLastUsed());
                ps.setTimestamp(6, session.getExprTime());
                ps.executeUpdate();
                ServiceLogger.LOGGER.info("Session has been created and inserted into database.");
                return new LoginSessionResponseModel(Result.LOGIN_SUCCESSFUL, session.getSessionID().toString()).buildResponse();
            }
            else
            {
                ServiceLogger.LOGGER.info("Password doesn't match.");
                return new LoginSessionResponseModel(Result.PASSWORD_DO_NOT_MATCH, null).buildResponse();
            }
        }
        catch (Exception e)
        {
            ServiceLogger.LOGGER.info("Error during sql operations.");
            return Util.internal_server_error();
        }
    }

    @Path("session")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response verifiy_session(@Context HttpHeaders headers, String jsonText)
    {
        SessionLogoutRequestModel requestModel;
        ObjectMapper mapper = new ObjectMapper();
        Timestamp currentTime = new Timestamp(System.currentTimeMillis());
        ServiceLogger.LOGGER.info("Session request received.");
        ServiceLogger.LOGGER.info(jsonText);
        try
        {
            requestModel = mapper.readValue(jsonText, SessionLogoutRequestModel.class);
        }
        catch (JsonParseException e)
        {
            ServiceLogger.LOGGER.info("JSON parse error.");
            return new LoginSessionResponseModel(Result.JSON_PARSE_ERROR, null).buildResponse();
        }
        catch (JsonMappingException e)
        {
            ServiceLogger.LOGGER.info("JSON mapping error.");
            return new LoginSessionResponseModel(Result.JSON_MAPPING_ERROR, null).buildResponse();
        }
        catch (Exception e)
        {
            ServiceLogger.LOGGER.info("Unknown error has occurred.");
            return Util.internal_server_error();
        }
        if(requestModel.getSession_id().length() != 128)
        {
            ServiceLogger.LOGGER.info("Token length is invalid.");
            return new LoginSessionResponseModel(Result.TOKEN_INVALID_LENGTH, null).buildResponse();
        }
        ServiceLogger.LOGGER.info("Requestmodel: " + requestModel);
        ServiceLogger.LOGGER.info("Session with email: " + requestModel.getEmail());
        switch (validateEmail(requestModel.getEmail()))
        {
            case 1:
                ServiceLogger.LOGGER.info("Email address has invalid length.");
                return new LoginSessionResponseModel(Result.EMAIL_INVALID_LENGTH, null).buildResponse();
            case 2:
                ServiceLogger.LOGGER.info("Email address has invalid format.");
                return new LoginSessionResponseModel(Result.EMAIL_INVALID_FORMAT, null).buildResponse();
        }
        if(!userExist(requestModel.getEmail())) {
            ServiceLogger.LOGGER.info("User does not exist.");
            return new BaseResponseModel(Result.USER_NOT_FOUND).buildResponse();
        }
        try {
            PreparedStatement ps = IDMService.getCon().prepareStatement("SELECT * FROM session WHERE email = ?");
            ps.setString(1, requestModel.getEmail());
            ResultSet rs = ps.executeQuery();
            boolean foundSession = false;
            if(!rs.isBeforeFirst()) //result set empty
            {
                ServiceLogger.LOGGER.info("No sessions found, user does not exist.");
                return new LoginSessionResponseModel(Result.USER_NOT_FOUND, null).buildResponse();
            }
            while(rs.next())
            {
                if(rs.getString("session_id").equals(requestModel.getSession_id()))
                {
                    foundSession = true;
                    break;
                }
            }
            if(!foundSession)
            {
                ServiceLogger.LOGGER.info("Session does not exist");
                return new LoginSessionResponseModel(Result.SESSION_NOT_FOUND, null).buildResponse();
            }
            switch (rs.getInt("status"))
            {
                case Session.ACTIVE:
                    ServiceLogger.LOGGER.info("Requested session is active.");
                    Timestamp lastUsed = rs.getTimestamp("last_used"), expiration = rs.getTimestamp("expr_time");
                    botCatcher(requestModel.getEmail(), currentTime, lastUsed);
                    if(currentTime.getTime() - lastUsed.getTime() > Session.SESSION_TIMEOUT)
                    {
                        ServiceLogger.LOGGER.info("Requested session timed out.");
                        ps = IDMService.getCon().prepareStatement("UPDATE session SET status = ? WHERE session_id = ? AND email = ?");
                        ps.setInt(1, Session.REVOKED);
                        ps.setString(2, requestModel.getSession_id());
                        ps.setString(3, requestModel.getEmail());
                        ps.executeUpdate();
                        return new LoginSessionResponseModel(Result.SESSION_REVOKED, null).buildResponse();
                    }
                    if(currentTime.getTime() - expiration.getTime() > 0)
                    {
                        ServiceLogger.LOGGER.info("Requested session passed expiration time.");
                        ps = IDMService.getCon().prepareStatement("UPDATE session SET status = ? WHERE session_id = ? AND email = ?");
                        ps.setInt(1, Session.EXPIRED);
                        ps.setString(2, requestModel.getSession_id());
                        ps.setString(3, requestModel.getEmail());
                        ps.executeUpdate();
                        return new LoginSessionResponseModel(Result.SESSION_EXPIRED, null).buildResponse();
                    }
                    if(expiration.getTime() - currentTime.getTime() < Session.SESSION_TIMEOUT) //passed expiration time but not timed out
                    {
                        ServiceLogger.LOGGER.info("Time difference between current and expiration has not passed timeout, creating a new session.");
                        ps = IDMService.getCon().prepareStatement("UPDATE session SET status = ? WHERE session_id = ? AND email = ?");
                        ps.setInt(1, Session.REVOKED);
                        ps.setString(2, requestModel.getSession_id());
                        ps.setString(3, requestModel.getEmail());
                        ps.executeUpdate();
                        Session session = Session.createSession(requestModel.getEmail());
                        ps = IDMService.getCon().prepareStatement("INSERT INTO session VALUES (?, ?, ?, ?, ?, ?)");
                        ps.setString(1, session.getSessionID().toString());
                        ps.setString(2, session.getEmail());
                        ps.setInt(3, Session.ACTIVE);
                        ps.setTimestamp(4, session.getTimeCreated());
                        ps.setTimestamp(5, session.getLastUsed());
                        ps.setTimestamp(6, session.getExprTime());
                        ps.executeUpdate();
                        ServiceLogger.LOGGER.info("Session has been created and inserted into database.");
                        return new LoginSessionResponseModel(Result.SESSION_ACTIVE, session.getSessionID().toString()).buildResponse();
                    }
                    ServiceLogger.LOGGER.info("Session is still good, updating last_used time.");
                    ps = IDMService.getCon().prepareStatement("UPDATE session SET last_used = ? WHERE session_id = ? AND email = ?");
                    ps.setTimestamp(1, currentTime);
                    ps.setString(2, requestModel.getSession_id());
                    ps.setString(3, requestModel.getEmail());
                    ps.executeUpdate();
                    return new LoginSessionResponseModel(Result.SESSION_ACTIVE, requestModel.getSession_id()).buildResponse();
                case Session.CLOSED:
                    ServiceLogger.LOGGER.info("Requested session is closed.");
                    return new LoginSessionResponseModel(Result.SESSION_CLOSED, null).buildResponse();
                case Session.EXPIRED:
                    ServiceLogger.LOGGER.info("Requested session is expired.");
                    return new LoginSessionResponseModel(Result.SESSION_EXPIRED, null).buildResponse();
                case Session.REVOKED:
                    ServiceLogger.LOGGER.info("Requested session is revoked.");
                    return new LoginSessionResponseModel(Result.SESSION_REVOKED, null).buildResponse();
            }
        }
        catch (Exception e) {
            ServiceLogger.LOGGER.info("Error during sql operations.");
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
        ServiceLogger.LOGGER.info("Session did not match any condition.");
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
    }

    @Path("privilege")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response privilege(@Context HttpHeaders headers, String jsonText)
    {
        PrivilegeRequestModel requestModel;
        ObjectMapper mapper = new ObjectMapper();
        ServiceLogger.LOGGER.info("Session request received.");
        try
        {
            requestModel = mapper.readValue(jsonText, PrivilegeRequestModel.class);
        }
        catch (JsonParseException e)
        {
            ServiceLogger.LOGGER.info("JSON parse error.");
            return new BaseResponseModel(Result.JSON_PARSE_ERROR).buildResponse();
        }
        catch (JsonMappingException e)
        {
            ServiceLogger.LOGGER.info("JSON mapping error.");
            return new BaseResponseModel(Result.JSON_MAPPING_ERROR).buildResponse();
        }
        catch (Exception e)
        {
            ServiceLogger.LOGGER.info("Unknown error has occurred.");
            return Util.internal_server_error();
        }
        if(requestModel.getPlevel() < 1 || requestModel.getPlevel() > 5)
        {
            ServiceLogger.LOGGER.info("Requested privilege level out of range.");
            return new BaseResponseModel(Result.PLEVEL_OUT_OF_RANGE).buildResponse();
        }
        switch (validateEmail(requestModel.getEmail()))
        {
            case 1:
                ServiceLogger.LOGGER.info("Email address has invalid length.");
                return new BaseResponseModel(Result.EMAIL_INVALID_LENGTH).buildResponse();
            case 2:
                ServiceLogger.LOGGER.info("Email address has invalid format.");
                return new BaseResponseModel(Result.EMAIL_INVALID_FORMAT).buildResponse();
        }
        if(!userExist(requestModel.getEmail())) {
            ServiceLogger.LOGGER.info("User does not exist.");
            return new BaseResponseModel(Result.USER_NOT_FOUND).buildResponse();
        }
        try {
            PreparedStatement ps = IDMService.getCon().prepareStatement("SELECT plevel FROM user WHERE email = ?");
            ps.setString(1, requestModel.getEmail());
            ResultSet rs = ps.executeQuery();
            if(!rs.next())
            {
                ServiceLogger.LOGGER.info("User does not exist.");
                return new BaseResponseModel(Result.USER_NOT_FOUND).buildResponse();
            }
            if(rs.getInt("plevel") <= requestModel.getPlevel())
            {
                ServiceLogger.LOGGER.info("User has sufficient privilege level.");
                return new BaseResponseModel(Result.SUFFICIENT_PLEVEL).buildResponse();
            }
            return new BaseResponseModel(Result.INSUFFICIENT_PLEVEL).buildResponse();
        }
        catch (Exception e) {
            ServiceLogger.LOGGER.info("Error with sql.");
            return Util.internal_server_error();
        }
    }

    @Path("logout")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response logout(@Context HttpHeaders headers, String jsonText)
    {
        SessionLogoutRequestModel requestModel;
        ObjectMapper mapper = new ObjectMapper();
        ServiceLogger.LOGGER.info("Session request received.");
        try
        {
            requestModel = mapper.readValue(jsonText, SessionLogoutRequestModel.class);
        }
        catch (JsonParseException e)
        {
            ServiceLogger.LOGGER.info("JSON parse error.");
            return new BaseResponseModel(Result.JSON_PARSE_ERROR).buildResponse();
        }
        catch (JsonMappingException e)
        {
            ServiceLogger.LOGGER.info("JSON mapping error.");
            return new BaseResponseModel(Result.JSON_MAPPING_ERROR).buildResponse();
        }
        catch (Exception e)
        {
            ServiceLogger.LOGGER.info("Unknown error has occurred.");
            return Util.internal_server_error();
        }
        switch (validateEmail(requestModel.getEmail()))
        {
            case 1:
                ServiceLogger.LOGGER.info("Email address has invalid length.");
                return new BaseResponseModel(Result.EMAIL_INVALID_LENGTH).buildResponse();
            case 2:
                ServiceLogger.LOGGER.info("Email address has invalid format.");
                return new BaseResponseModel(Result.EMAIL_INVALID_FORMAT).buildResponse();
        }
        if(!userExist(requestModel.getEmail())) {
            ServiceLogger.LOGGER.info("User does not exist.");
            return new BaseResponseModel(Result.USER_NOT_FOUND).buildResponse();
        }
        try {
            int session = Util.getSession(requestModel.getEmail(), requestModel.getSession_id());
            switch (session) {
                case Session.CLOSED:
                    ServiceLogger.LOGGER.info("Requested session is closed.");
                    return new BaseResponseModel(Result.SESSION_CLOSED).buildResponse();
                case Session.EXPIRED:
                    ServiceLogger.LOGGER.info("Requested session is expired.");
                    return new BaseResponseModel(Result.SESSION_EXPIRED).buildResponse();
                case Session.REVOKED:
                    ServiceLogger.LOGGER.info("Requested session is revoked.");
                    return new BaseResponseModel(Result.SESSION_REVOKED).buildResponse();
                case 5:
                    ServiceLogger.LOGGER.info("Session not found.");
                    return new BaseResponseModel(Result.SESSION_NOT_FOUND).buildResponse();
                case 6:
                    ServiceLogger.LOGGER.info("Error with sql.");
                    return Util.internal_server_error();
            }
            String query = "UPDATE session SET status = ? WHERE email = ? AND session_id = ?";
            PreparedStatement ps = IDMService.getCon().prepareStatement(query);
            ps.setInt(1, Session.CLOSED);
            ps.setString(2, requestModel.getEmail());
            ps.setString(3, requestModel.getSession_id());
            ps.executeUpdate();
            return new BaseResponseModel(Result.LOGOUT_SUCCESSFUL).buildResponse();
        } catch (Exception e) {
            ServiceLogger.LOGGER.info("Error with sql.");
            return Util.internal_server_error();
        }
    }

    @Path("pword/update")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response passwordUpdate(@Context HttpHeaders headers, String jsonText)
    {
        PasswordUpdateRequestModel requestModel;
        ObjectMapper mapper = new ObjectMapper();
        ServiceLogger.LOGGER.info("Session request received.");
        try
        {
            requestModel = mapper.readValue(jsonText, PasswordUpdateRequestModel.class);
        }
        catch (JsonParseException e)
        {
            ServiceLogger.LOGGER.info("JSON parse error.");
            return new BaseResponseModel(Result.JSON_PARSE_ERROR).buildResponse();
        }
        catch (JsonMappingException e)
        {
            ServiceLogger.LOGGER.info("JSON mapping error.");
            return new BaseResponseModel(Result.JSON_MAPPING_ERROR).buildResponse();
        }
        catch (Exception e)
        {
            ServiceLogger.LOGGER.info("Unknown error has occurred.");
            return Util.internal_server_error();
        }
        switch (validateEmail(requestModel.getEmail()))
        {
            case 1:
                ServiceLogger.LOGGER.info("Email address has invalid length.");
                return new BaseResponseModel(Result.EMAIL_INVALID_LENGTH).buildResponse();
            case 2:
                ServiceLogger.LOGGER.info("Email address has invalid format.");
                return new BaseResponseModel(Result.EMAIL_INVALID_FORMAT).buildResponse();
        }
        switch (validatePassword(requestModel.getPassword()))
        {
            case -1:
                ServiceLogger.LOGGER.info("Password has invalid length.");
                return new BaseResponseModel(Result.PASSWORD_INVALID_LENGTH).buildResponse();
            case 1:
                ServiceLogger.LOGGER.info("Password does not meet length requirements.");
                return new BaseResponseModel(Result.PASSWORD_LENGTH_REQUIREMENT).buildResponse();
            case 2:
                ServiceLogger.LOGGER.info("Password does not meet character requirements.");
                return new BaseResponseModel(Result.PASSWORD_CHARACTER_REQUIREMENT).buildResponse();
        }
        if(!userExist(requestModel.getEmail())) {
            ServiceLogger.LOGGER.info("User does not exist.");
            return new BaseResponseModel(Result.USER_NOT_FOUND).buildResponse();
        }
        int session = Util.getSession(requestModel.getEmail(), requestModel.getSession_id());
        switch (session) {
            case Session.CLOSED:
                ServiceLogger.LOGGER.info("Requested session is closed.");
                return new BaseResponseModel(Result.SESSION_CLOSED).buildResponse();
            case Session.EXPIRED:
                ServiceLogger.LOGGER.info("Requested session is expired.");
                return new BaseResponseModel(Result.SESSION_EXPIRED).buildResponse();
            case Session.REVOKED:
                ServiceLogger.LOGGER.info("Requested session is revoked.");
                return new BaseResponseModel(Result.SESSION_REVOKED).buildResponse();
            case 5:
                ServiceLogger.LOGGER.info("Session not found.");
                return new BaseResponseModel(Result.SESSION_NOT_FOUND).buildResponse();
            case 6:
                ServiceLogger.LOGGER.info("Error with sql.");
                return Util.internal_server_error();
        }
        ServiceLogger.LOGGER.info("Email and password has correct length and format, salt and hashing password.");
        byte salt[] = Crypto.genSalt();
        char pw[] = requestModel.getPassword();
        byte hashedPW[] = Crypto.hashPassword(pw, salt, Crypto.ITERATIONS, Crypto.KEY_LENGTH);
        String encodedSalt = Hex.encodeHexString(salt), encodedPW = Hex.encodeHexString(hashedPW);
        ServiceLogger.LOGGER.info("Finished hashing password.");
        try {
            PreparedStatement ps = IDMService.getCon().prepareStatement("UPDATE user SET salt = ?, pword = ? WHERE email = ?");
            ps.setString(1, encodedSalt);
            ps.setString(2, encodedPW);
            ps.setString(3, requestModel.getEmail());
            ps.executeUpdate();
        }
        catch (SQLException e) {
            ServiceLogger.LOGGER.info("Error updating user.");
            return Util.internal_server_error();
        }
        return new BaseResponseModel(Result.PASSWORD_UPDATED).buildResponse();
    }

    @Path("pword/forget")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response passwordForget(@Context HttpHeaders headers, String jsonText)
    {
        BaseRequestModel requestModel;
        ObjectMapper mapper = new ObjectMapper();
        ServiceLogger.LOGGER.info("Session request received.");
        try
        {
            requestModel = mapper.readValue(jsonText, BaseRequestModel.class);
        }
        catch (JsonParseException e)
        {
            ServiceLogger.LOGGER.info("JSON parse error.");
            return new BaseResponseModel(Result.JSON_PARSE_ERROR).buildResponse();
        }
        catch (JsonMappingException e)
        {
            ServiceLogger.LOGGER.info("JSON mapping error.");
            return new BaseResponseModel(Result.JSON_MAPPING_ERROR).buildResponse();
        }
        catch (Exception e)
        {
            ServiceLogger.LOGGER.info("Unknown error has occurred.");
            return Util.internal_server_error();
        }
        switch (validateEmail(requestModel.getEmail()))
        {
            case 1:
                ServiceLogger.LOGGER.info("Email address has invalid length.");
                return new BaseResponseModel(Result.EMAIL_INVALID_LENGTH).buildResponse();
            case 2:
                ServiceLogger.LOGGER.info("Email address has invalid format.");
                return new BaseResponseModel(Result.EMAIL_INVALID_FORMAT).buildResponse();
        }
        if(!userExist(requestModel.getEmail())) {
            ServiceLogger.LOGGER.info("User does not exist.");
            return new BaseResponseModel(Result.USER_NOT_FOUND).buildResponse();
        }
        String token = Hex.encodeHexString(Crypto.genSalt());
        Email email = EmailBuilder.startingBlank()
                .from("FabFlix Customer Support", "fabflix@fabflix.com")
                .to(requestModel.getEmail())
                .withSubject("Password Reset")
                .withPlainText("Reset token: " + token)
                .buildEmail();
        MailerBuilder.withSMTPServer("smtp.gmail.com", 25, "email@email.com", "password")
                .buildMailer().sendMail(email);
        try {
            PreparedStatement ps = IDMService.getCon().prepareStatement("UPDATE user SET reset_token = ? WHERE email = ?");
            ps.setString(1, token);
            ps.setString(2, requestModel.getEmail());
            ps.executeUpdate();
        } catch (Exception e) {
            ServiceLogger.LOGGER.info(e.getMessage());
            return Util.internal_server_error();
        }
        return new BaseResponseModel(Result.TOKEN_EMAILED).buildResponse();
    }

    @Path("pword/reset")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response passwordReset(@Context HttpHeaders headers, String jsonText)
    {
        PasswordResetRequestModel requestModel;
        ObjectMapper mapper = new ObjectMapper();
        ServiceLogger.LOGGER.info("Session request received.");
        try
        {
            requestModel = mapper.readValue(jsonText, PasswordResetRequestModel.class);
        }
        catch (JsonParseException e)
        {
            ServiceLogger.LOGGER.info("JSON parse error.");
            return new BaseResponseModel(Result.JSON_PARSE_ERROR).buildResponse();
        }
        catch (JsonMappingException e)
        {
            ServiceLogger.LOGGER.info("JSON mapping error.");
            return new BaseResponseModel(Result.JSON_MAPPING_ERROR).buildResponse();
        }
        catch (Exception e)
        {
            ServiceLogger.LOGGER.info("Unknown error has occurred.");
            return Util.internal_server_error();
        }
        switch (validateEmail(requestModel.getEmail()))
        {
            case 1:
                ServiceLogger.LOGGER.info("Email address has invalid length.");
                return new BaseResponseModel(Result.EMAIL_INVALID_LENGTH).buildResponse();
            case 2:
                ServiceLogger.LOGGER.info("Email address has invalid format.");
                return new BaseResponseModel(Result.EMAIL_INVALID_FORMAT).buildResponse();
        }
        switch (validatePassword(requestModel.getPassword()))
        {
            case -1:
                ServiceLogger.LOGGER.info("Password has invalid length.");
                return new BaseResponseModel(Result.PASSWORD_INVALID_LENGTH).buildResponse();
            case 1:
                ServiceLogger.LOGGER.info("Password does not meet length requirements.");
                return new BaseResponseModel(Result.PASSWORD_LENGTH_REQUIREMENT).buildResponse();
            case 2:
                ServiceLogger.LOGGER.info("Password does not meet character requirements.");
                return new BaseResponseModel(Result.PASSWORD_CHARACTER_REQUIREMENT).buildResponse();
        }
        if(!userExist(requestModel.getEmail())) {
            ServiceLogger.LOGGER.info("User does not exist.");
            return new BaseResponseModel(Result.USER_NOT_FOUND).buildResponse();
        }
        try {
            PreparedStatement ps = IDMService.getCon().prepareStatement("SELECT * FROM user WHERE email = ? AND reset_token = ?");
            ps.setString(1, requestModel.getEmail());
            ps.setString(2, requestModel.getReset_token());
            ResultSet rs = ps.executeQuery();
            if(rs.next()) {
                byte salt[] = Crypto.genSalt();
                char pw[] = requestModel.getPassword();
                byte hashedPW[] = Crypto.hashPassword(pw, salt, Crypto.ITERATIONS, Crypto.KEY_LENGTH);
                String encodedSalt = Hex.encodeHexString(salt), encodedPW = Hex.encodeHexString(hashedPW);
                ServiceLogger.LOGGER.info("Finished hashing password.");
                ps = IDMService.getCon().prepareStatement("UPDATE user SET salt = ?, pword = ?, reset_token = ? WHERE email = ?");
                ps.setString(1, encodedSalt);
                ps.setString(2, encodedPW);
                ps.setNull(3, Types.VARCHAR);
                ps.setString(4, requestModel.getEmail());
                ps.executeUpdate();
                return new BaseResponseModel(Result.PASSWORD_UPDATED).buildResponse();
            } else {
                return new BaseResponseModel(Result.TOKEN_INVALID).buildResponse();
            }
        } catch (Exception e) {
            ServiceLogger.LOGGER.info(e.getMessage());
            return Util.internal_server_error();
        }
    }

    private int validatePassword(char[] password)
    {
        if(password == null)
            return -1;
        if(password.length == 0)
            return -1;
        if(password.length < 7 || password.length > 16)
            return 1;
        boolean lower = false, upper = false, numeric = false;
        for(char c: password)
        {
            if(c >= '0' && c <= '9')
                numeric = true;
            else if(c >= 'A' && c <= 'Z')
                upper = true;
            else if(c >= 'a' && c <= 'z')
                lower = true;
            else
                return 2;
        }
        if(lower && upper && numeric)
            return 0;
        return 2;
    }

    private int validateEmail(String email)
    {
        if(email == null)
            return 1;
        if(email.length() == 0)
            return 1;
        if(!email.matches("[a-zA-Z0-9@.]+")) // contains only alphanumeric + @ and .
            return 2;
        if(email.matches("^[a-zA-Z0-9]+@[a-zA-Z0-9]+\\.[a-zA-Z0-9]+$")) // matches the format
            return 0;
        return 2;
    }

    private boolean userExist(String email)
    {
        String query = "SELECT * FROM user WHERE email = ?";
        try {
            PreparedStatement ps = IDMService.getCon().prepareStatement(query);
            ps.setString(1, email);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                if (rs.getInt("status") != 1) {
                    return false;
                }
                return true;
            }
            return false;
        } catch(Exception e) {
            ServiceLogger.LOGGER.info(e.getMessage());
            return false;
        }
    }

    private void botCatcher(String email, Timestamp currentTime, Timestamp last_used)
    {
        if (currentTime.getTime() <= (last_used.getTime() + IDMService.getServiceConfigs().getRequestInterval())) {
            try {
                PreparedStatement ps = IDMService.getCon().prepareStatement("UPDATE user SET counter = counter + 1 WHERE email = ?");
                ps.setString(1, email);
                ps.executeUpdate();
                checkUserCounter(email);
            } catch (Exception e) {
                ServiceLogger.LOGGER.info(e.getMessage());
            }
        } else {
            try {
                PreparedStatement ps = IDMService.getCon().prepareStatement("UPDATE user SET counter = 0 WHERE email = ?");
                ps.setString(1, email);
                ps.executeUpdate();
            } catch (Exception e) {
                ServiceLogger.LOGGER.info(e.getMessage());
            }
        }
    }

    private void checkUserCounter(String email)
    {
        try {
            PreparedStatement ps = IDMService.getCon().prepareStatement("SELECT counter FROM user WHERE email = ?");
            ps.setString(1, email);
            ResultSet rs = ps.executeQuery();
            rs.next();
            if(rs.getInt("counter") > IDMService.getServiceConfigs().getMaxRapidRequest()) {
                ps = IDMService.getCon().prepareStatement("UPDATE user SET status = 3 WHERE email = ?");
                ps.setString(1, email);
                ps.executeUpdate();
                ps = IDMService.getCon().prepareStatement("UPDATE session SET status = ? WHERE status = ? AND email = ?");
                ps.setInt(1, Session.REVOKED);
                ps.setInt(2, Session.ACTIVE);
                ps.setString(3, email);
                ps.executeUpdate();
            }
        } catch (Exception e) {
            ServiceLogger.LOGGER.info(e.getMessage());
        }
    }
}
