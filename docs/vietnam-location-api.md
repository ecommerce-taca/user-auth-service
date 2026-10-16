# Vietnam location catalog and delivery addresses

## Public catalog endpoints

The service loads `data/vietnam-address.json` once at startup and exposes:

- `GET /api/v1/locations/vn/provinces`
- `GET /api/v1/locations/vn/provinces/{provinceCode}/wards`

Both endpoints are public and return `Cache-Control: max-age=86400, public`.
The UI displays each item's `name` and uses its `code` as the option value.

## Address write contract

`POST /api/v1/users/me/addresses` and
`PUT /api/v1/users/me/addresses/{addressId}` accept the following location
fields:

```json
{
  "recipient": "Nguyen Van A",
  "phone": "+84901234567",
  "line1": "123 Nguyen Hue",
  "line2": null,
  "country_code": "VN",
  "province_code": "79",
  "ward_code": "26740",
  "postal_code": null,
  "is_default": true
}
```

`recipient`, `phone`, `line1`, `country_code`, `province_code`, and
`ward_code` are required. The only supported country is currently `VN`.
The ward must belong to the selected province.

Clients do not send province or ward names. The service resolves canonical
names from the catalog and stores both names and codes. New Vietnamese
addresses do not use a district; the legacy `district` column remains
nullable for backward compatibility.

Existing records from before migration `V021` keep their province and ward
names and can have null location codes. Updating one of those records through
the API supplies and persists canonical codes.

## Seller warehouse address

`PUT /api/v1/seller/onboarding/warehouse` follows the same two-level Vietnam
administrative model: `address.ward` and `address.province` are required, while
the legacy `address.district` field is optional. New clients should omit it;
the service accepts an omitted, `null`, or blank value and stores `null`.
