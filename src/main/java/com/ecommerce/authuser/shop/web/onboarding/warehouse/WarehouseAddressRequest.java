package com.ecommerce.authuser.shop.web.onboarding.warehouse;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonSetter;

import tools.jackson.databind.JsonNode;

import java.util.LinkedHashSet;
import java.util.Set;

public class WarehouseAddressRequest {

    private String line1;
    private String line2;
    private String ward;
    private String district;
    private String province;
    private String postalCode;

    private boolean invalidFieldType;

    private final Set<String> unsupportedFields = new LinkedHashSet<>();

    @JsonSetter("line1")
    public void setLine1(JsonNode value) {
        line1 = readRequiredString(value);
    }

    @JsonSetter("line2")
    public void setLine2(JsonNode value) {
        line2 = readOptionalString(value);
    }

    @JsonSetter("ward")
    public void setWard(JsonNode value) {
        ward = readRequiredString(value);
    }

    @JsonSetter("district")
    public void setDistrict(JsonNode value) {
        district = readOptionalString(value);
    }

    @JsonSetter("province")
    public void setProvince(JsonNode value) {
        province = readRequiredString(value);
    }

    @JsonSetter("postal_code")
    public void setPostalCode(JsonNode value) {
        postalCode = readOptionalString(value);
    }

    @JsonAnySetter
    public void captureUnsupportedField(
            String name,
            JsonNode value
    ) {
        unsupportedFields.add(name);
    }

    public String line1() {
        return line1;
    }

    public String line2() {
        return line2;
    }

    public String ward() {
        return ward;
    }

    public String district() {
        return district;
    }

    public String province() {
        return province;
    }

    public String postalCode() {
        return postalCode;
    }

    public boolean invalid() {
        return invalidFieldType || !unsupportedFields.isEmpty();
    }

    private String readRequiredString(JsonNode value) {

        if (value == null
                || value.isNull()
                || !value.isTextual()) {

            invalidFieldType = true;
            return null;
        }

        return value.textValue();
    }

    private String readOptionalString(JsonNode value) {

        if (value == null || value.isNull()) {
            return null;
        }

        if (!value.isTextual()) {
            invalidFieldType = true;
            return null;
        }

        return value.textValue();
    }
}
