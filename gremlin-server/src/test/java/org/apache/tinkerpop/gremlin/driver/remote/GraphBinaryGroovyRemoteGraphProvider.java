/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.tinkerpop.gremlin.driver.remote;

import org.apache.tinkerpop.gremlin.structure.Graph;
import org.apache.tinkerpop.gremlin.util.ser.SerializersV4;

/**
 * @author Stephen Mallette (http://stephen.genoprime.com)
 */
@Graph.OptOut(
        test = "org.apache.tinkerpop.gremlin.process.traversal.step.map.MatchTest$GreedyMatchTraversals",
        method = "*",
        reason = "MatchAlgorithmStrategy construction doesn't work for gremlin-groovy")
public class GraphBinaryGroovyRemoteGraphProvider extends AbstractRemoteGraphProvider implements AutoCloseable {
    public GraphBinaryGroovyRemoteGraphProvider() {
        super(createClusterBuilder(SerializersV4.GRAPHBINARY_V4).create(), false, "groovy-test");
    }
}