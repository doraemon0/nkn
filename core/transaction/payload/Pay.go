package payload

import (
	"io"

	"encoding/json"
	. "github.com/nknorg/nkn/common"
)

type Pay struct {
	Payer  Uint160
	Amount Fixed64
}

func (p *Pay) Data(version byte) []byte {
	return []byte{0}
}

func (p *Pay) Serialize(w io.Writer, version byte) error {
	_, err := p.Payer.Serialize(w)
	if err != nil {
		return err
	}
	err = p.Amount.Serialize(w)
	if err != nil {
		return err
	}

	return nil
}

func (p *Pay) Deserialize(r io.Reader, version byte) error {
	payer := new(Uint160)
	err := payer.Deserialize(r)
	if err != nil {
		return err
	}
	p.Payer = *payer

	amount := new(Fixed64)
	err = amount.Deserialize(r)
	if err != nil {
		return err
	}
	p.Amount = *amount

	return nil
}

func (p *Pay) MarshalJson() ([]byte, error) {
	payer, err := p.Payer.ToAddress()
	if err != nil {
		return nil, err
	}
	payInfo := &PayInfo{
		Payer:  payer,
		Amount: p.Amount.String(),
	}
	data, err := json.Marshal(payInfo)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (p *Pay) UnmarshalJson(data []byte) error {
	payInfo := new(PayInfo)
	var err error
	if err = json.Unmarshal(data, &payInfo); err != nil {
		return err
	}

	scriptHash, err := ToScriptHash(payInfo.Payer)
	if err != nil {
		return err
	}
	p.Payer = scriptHash

	amount, err := StringToFixed64(payInfo.Amount)
	if err != nil {
		return err
	}
	p.Amount = amount

	return nil
}
