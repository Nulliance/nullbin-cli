package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/Nulliance/nullbin-cli/link"
)

// Delete permanently deletes a paste using its parsed delete link.
func (c *Client) Delete(ctx context.Context, dl *link.DeleteLink) error {
	if dl == nil || !link.ValidID(dl.ID) || !link.ValidToken(dl.DeleteToken) {
		return link.ErrInvalidURL
	}
	apiOrigin, err := c.ResolveAPIOrigin(ctx)
	if err != nil {
		return err
	}

	reqCtx, cancel := context.WithTimeout(ctx, defaultRequestTimeout)
	defer cancel()

	req, err := c.newRequest(reqCtx, http.MethodDelete, fmt.Sprintf("%s/api/v1/pastes/%s", apiOrigin, dl.ID), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Nullbin-Delete-Token", dl.DeleteToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("deleting paste: %w", err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode != http.StatusNoContent {
		return parseAPIError(resp)
	}
	return nil
}

// ListRecipients returns the state of every separate recipient link (0-based index).
func (c *Client) ListRecipients(ctx context.Context, dl *link.DeleteLink) ([]RecipientState, error) {
	if dl == nil || !link.ValidID(dl.ID) || !link.ValidToken(dl.DeleteToken) {
		return nil, link.ErrInvalidURL
	}
	apiOrigin, err := c.ResolveAPIOrigin(ctx)
	if err != nil {
		return nil, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, defaultRequestTimeout)
	defer cancel()

	req, err := c.newRequest(reqCtx, http.MethodGet, fmt.Sprintf("%s/api/v1/pastes/%s/recipients", apiOrigin, dl.ID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Nullbin-Delete-Token", dl.DeleteToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("listing recipients: %w", err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, parseAPIError(resp)
	}

	obj, err := readBoundedJSONObject(resp, maxJSONBytes)
	if err != nil {
		return nil, err
	}
	rawList, ok := obj["recipients"].([]any)
	if !ok || len(rawList) < MinRecipients || len(rawList) > MaxRecipients {
		return nil, errors.New("server sent invalid recipients list")
	}

	out := make([]RecipientState, len(rawList))
	for i, item := range rawList {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("server sent invalid recipient entry")
		}
		opensNum, ok := m["opens"].(json.Number)
		if !ok {
			return nil, errors.New("server sent invalid recipient opens")
		}
		opens, err := opensNum.Int64()
		if err != nil || opens < 0 {
			return nil, errors.New("server sent invalid recipient opens")
		}

		var maxOpens *int
		if rawMax := m["max_opens"]; rawMax != nil {
			mn, ok := rawMax.(json.Number)
			if !ok {
				return nil, errors.New("server sent invalid recipient max_opens")
			}
			mv, err := mn.Int64()
			if err != nil || mv < 1 || mv > MaxBurnReads {
				return nil, errors.New("server sent invalid recipient max_opens")
			}
			mi := int(mv)
			maxOpens = &mi
		}

		revoked, ok := m["revoked"].(bool)
		if !ok {
			return nil, errors.New("server sent invalid recipient revoked flag")
		}
		out[i] = RecipientState{
			Index:    i,
			Opens:    int(opens),
			MaxOpens: maxOpens,
			Revoked:  revoked,
		}
	}
	return out, nil
}

// RevokeRecipient permanently revokes recipient link n (0-based index).
func (c *Client) RevokeRecipient(ctx context.Context, dl *link.DeleteLink, index int) error {
	if dl == nil || !link.ValidID(dl.ID) || !link.ValidToken(dl.DeleteToken) {
		return link.ErrInvalidURL
	}
	if index < 0 || index >= MaxRecipients {
		return fmt.Errorf("recipient index must be between 0 and %d", MaxRecipients-1)
	}
	apiOrigin, err := c.ResolveAPIOrigin(ctx)
	if err != nil {
		return err
	}

	reqCtx, cancel := context.WithTimeout(ctx, defaultRequestTimeout)
	defer cancel()

	req, err := c.newRequest(reqCtx, http.MethodPost, fmt.Sprintf("%s/api/v1/pastes/%s/recipients/%d/revoke", apiOrigin, dl.ID, index), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Nullbin-Delete-Token", dl.DeleteToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("revoking recipient %d: %w", index, err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode != http.StatusNoContent {
		return parseAPIError(resp)
	}
	return nil
}
