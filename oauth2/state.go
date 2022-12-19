package oauth2

import "sync"

type state struct {
	redirectURI   string
	codeChallenge string
}

type codeCache struct {
	codes map[string]*state
	lock  sync.Mutex
}

func (c *codeCache) add(code string, state *state) {
	c.lock.Lock()
	c.codes[code] = state
	c.lock.Unlock()
}

func (c *codeCache) del(code string) *state {
	c.lock.Lock()
	state := c.codes[code]
	delete(c.codes, code)
	c.lock.Unlock()
	return state
}
