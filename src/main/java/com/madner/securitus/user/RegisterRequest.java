package com.madner.securitus.user;

public record RegisterRequest(String firstname, String lastname, String email, String password) {
}
