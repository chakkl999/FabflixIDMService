package edu.uci.ics.chakkl.service.idm.util;

import javax.ws.rs.core.Response;

public enum Result {
    FOUND_MOVIE_WItH_SEARCH_PARAMETERS (210, "Found movie(s) with search parameters.", Response.Status.OK),
    NO_MOVIES_FOUND_WITH_SEARCH_PARAMETERS (211, "No movies found with search parameters.", Response.Status.OK),
    FOUND_PEOPLE_WITH_SEARCH_PARAMETERS (212, "Found people with search parameters.", Response.Status.OK),
    NO_PEOPLE_FOUND_WITH_SEARCH_PARAMETERS (213, "No people found with search parameters.", Response.Status.OK),
    PLEVEL_OUT_OF_RANGE (-14, "Privilege level out of valid range.", Response.Status.BAD_REQUEST),
    TOKEN_INVALID_LENGTH (-13, "Token has invalid length.", Response.Status.BAD_REQUEST),
    PASSWORD_INVALID_LENGTH (-12, "Password has invalid length.", Response.Status.BAD_REQUEST),
    EMAIL_INVALID_FORMAT (-11, "Email address has invalid format.", Response.Status.BAD_REQUEST),
    EMAIL_INVALID_LENGTH (-10, "Email address has invalid length.", Response.Status.BAD_REQUEST),
    JSON_PARSE_ERROR (-3, "JSON Parse Exception.", Response.Status.BAD_REQUEST),
    JSON_MAPPING_ERROR (-2, "JSON Mapping Exception.", Response.Status.BAD_REQUEST),
    PASSWORD_DO_NOT_MATCH (11, "Passwords do not match.", Response.Status.OK),
    PASSWORD_LENGTH_REQUIREMENT (12, "Password does not meet length requirements.", Response.Status.OK),
    PASSWORD_CHARACTER_REQUIREMENT (13, "Password does not meet character requirements.", Response.Status.OK),
    USER_NOT_FOUND (14, "User not found.", Response.Status.OK),
    USER_NOT_LOGGED_IN (17, "User not logged in.", Response.Status.OK),
    EMAIL_ALREADY_IN_USE (16, "Email already in use.", Response.Status.OK),
    QUANTITY_INVALID (33, "Quantity has invalid value.", Response.Status.OK),
    REGISTER_SUCCESSFUL (110, "User registered successfully.", Response.Status.OK),
    LOGIN_SUCCESSFUL (120, "User logged in successfully.", Response.Status.OK),
    LOGOUT_SUCCESSFUL (121, "User logged out successfully.", Response.Status.OK),
    SESSION_ACTIVE (130, "Session is active.", Response.Status.OK),
    SESSION_EXPIRED (131, "Session is expired.", Response.Status.OK),
    SESSION_CLOSED (132, "Session is closed.", Response.Status.OK),
    SESSION_REVOKED (133, "Session is revoked.", Response.Status.OK),
    SESSION_NOT_FOUND (134, "Session not found.", Response.Status.OK),
    SUFFICIENT_PLEVEL (140, "User has sufficient privilege level.", Response.Status.OK),
    INSUFFICIENT_PLEVEL (141, "User has insufficient privilege level.", Response.Status.OK),
    PASSWORD_UPDATED (150, "Password updated successfully.", Response.Status.OK),
    TOKEN_EMAILED (151, "Reset token emailed successfully.", Response.Status.OK),
    TOKEN_INVALID (152, "Invalid reset token.", Response.Status.OK),
    DUPLICATE_INSERTION (311, "Duplicate insertion.", Response.Status.OK),
    CART_ITEM_DOES_NOT_EXIST (312, "Shopping cart item does not exist.", Response.Status.OK),
    ORDER_HISTORY_NOT_EXIST (313, "Order history does not exist.", Response.Status.OK),
    ORDER_CREATION_FAILED (342, "Order creation failed.", Response.Status.OK),
    CART_INSERTION_SUCCESSFUL (3100, "Shopping cart item inserted successfully.", Response.Status.OK),
    CART_UPDATE_SUCCESSFUL (3110, "Shopping cart item updated successfully.", Response.Status.OK),
    CART_ITEM_DELETE_SUCCESSFUL (3120, "Shopping cart item deleted successfully.", Response.Status.OK),
    CART_RETRIEVE_SUCCESSFUL (3130, "Shopping cart retrieved successfully.", Response.Status.OK),
    CART_CLEAR_SUCCESSFUL (3140, "Shopping cart cleared successfully.", Response.Status.OK),
    CART_OPERATION_FAILED (3150, "Shopping cart operation failed.", Response.Status.OK),
    ORDER_PLACED_SUCCESSFUL (3400, "Order placed successfully.", Response.Status.OK),
    ORDER_RETRIEVED_SUCCESSFUL (3410, "Orders retrieved successfully.", Response.Status.OK),
    ORDER_COMPLETED (3420, "Order is completed successfully.", Response.Status.OK),
    TOKEN_NOT_FOUND (3421, "Token not found.", Response.Status.OK),
    ORDER_CANNOT_BE_COMPLETE (3422, "Order can not be completed.", Response.Status.OK);

    private final int resultCode;
    private final String message;
    private final Response.Status httpCode;

    Result(int resultCode, String message, Response.Status httpCode)
    {
        this.resultCode = resultCode;
        this.message = message;
        this.httpCode = httpCode;
    }

    public int getResultCode() {
        return resultCode;
    }

    public String getMessage() {
        return message;
    }

    public Response.Status getHttpCode() {
        return httpCode;
    }
}