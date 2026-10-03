package worker

import (
	"strings"

	"github.com/alpha-omega-security/harness"
)

const (
	modelDaybreakBlueID = "gpt-daybreak-blue-latest"
	modelGPT56SolID     = "gpt-5.6-sol"
	modelGPT6AstraID    = "gpt-6-astra"
	modelGPT6SolID      = "gpt-6-sol"
	modelGPT6LunaID     = "gpt-6-luna"
	perMillionTokens    = 1e6

	// Standard base list prices in USD per million tokens. The aggregate
	// Usage event cannot identify requests that crossed the long-context
	// threshold, so these deliberately remain base-rate estimates.
	// https://developers.openai.com/api/docs/pricing
	gpt6AstraInputPrice       = 10.00
	gpt6AstraOutputPrice      = 50.00
	gpt6AstraCachedInputPrice = 1.00
	gpt6AstraCacheWritePrice  = 12.50

	gpt6SolInputPrice       = 2.00
	gpt6SolOutputPrice      = 10.00
	gpt6SolCachedInputPrice = 0.20
	gpt6SolCacheWritePrice  = 2.50

	gpt6LunaInputPrice       = 0.10
	gpt6LunaOutputPrice      = 0.50
	gpt6LunaCachedInputPrice = 0.01
	gpt6LunaCacheWritePrice  = 0.125
)

// modelPrice is one model's standard base list price in USD per million tokens.
type modelPrice struct{ in, cachedIn, cacheWrite, out float64 }

var gpt6Pricing = map[string]modelPrice{
	modelGPT6AstraID: {gpt6AstraInputPrice, gpt6AstraCachedInputPrice, gpt6AstraCacheWritePrice, gpt6AstraOutputPrice},
	modelGPT6SolID:   {gpt6SolInputPrice, gpt6SolCachedInputPrice, gpt6SolCacheWritePrice, gpt6SolOutputPrice},
	modelGPT6LunaID:  {gpt6LunaInputPrice, gpt6LunaCachedInputPrice, gpt6LunaCacheWritePrice, gpt6LunaOutputPrice},
}

// CostFromUsage computes the dollar cost of one result event's token usage
// against the given model's list price. Harness owns the shared pricing table;
// local handling bridges the GPT-6 family until the module ships its pricing.
func CostFromUsage(model string, u Usage) float64 {
	price, ok := gpt6Pricing[normalizePricingModelID(model)]
	if !ok {
		return harness.CostFromUsage(model, u)
	}

	uncached := u.InputTokens - u.CacheReadTokens - u.CacheWriteTokens
	if uncached < 0 {
		uncached = 0
	}
	return (float64(uncached)*price.in +
		float64(u.CacheReadTokens)*price.cachedIn +
		float64(u.CacheWriteTokens)*price.cacheWrite +
		float64(u.OutputTokens)*price.out) / perMillionTokens
}

func normalizePricingModelID(id string) string {
	if slash := strings.LastIndexByte(id, '/'); slash >= 0 {
		id = id[slash+1:]
	}
	if bracket := strings.IndexByte(id, '['); bracket > 0 {
		id = id[:bracket]
	}
	return id
}
