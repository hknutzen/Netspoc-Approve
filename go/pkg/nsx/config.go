package nsx

func (s *State) LoadNetspoc(data []byte, fName string) error {
	cfg, err := s.parseConfig(data, fName)
	if err != nil {
		return err
	}
	if s.spocCfg == nil {
		s.spocCfg = cfg
	} else {
		s.mergeSpoc(cfg)
	}
	return nil
}

func (s *State) MoveNetspoc2DeviceConfig() {
	s.deviceCfg, s.spocCfg = s.spocCfg, nil
}

func (s *State) mergeSpoc(n2 *nsxConfig) {
	n1 := s.spocCfg
	n1.Groups = append(n1.Groups, n2.Groups...)
	n1.Services = append(n1.Services, n2.Services...)

POLICY:
	for _, p2 := range n2.Policies {
		for _, p1 := range n1.Policies {
			if p2.Id == p1.Id {
				p1.Rules = append(p1.Rules, p2.Rules...)
				continue POLICY
			}
		}
		n1.Policies = append(n1.Policies, p2)
	}
}
