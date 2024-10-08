/*
 * Engineering Ingegneria Informatica S.p.A.
 *
 * Copyright (C) 2023 Regione Emilia-Romagna
 * <p/>
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Affero General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 * <p/>
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package it.eng.crypto.data.util;

import java.io.InputStream;
import java.io.Reader;
import it.eng.crypto.exception.XmlParserException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.validation.Schema;

import org.w3c.dom.Document;

/**
 * A pool of XML parsers.
 */
public interface ParserPool {

    /**
     * Gets a builder from the pool.
     *
     * @return a builder from the pool
     *
     * @throws XmlParserException
     *             thrown if the document builder factory is misconfigured
     */
    public DocumentBuilder getBuilder() throws XmlParserException;

    /**
     * Returns a builder to the pool.
     *
     * @param builder
     *            the builder to return
     */
    public void returnBuilder(DocumentBuilder builder);

    /**
     * Convience method for creating a new document with a pooled builder.
     *
     * @return created document
     *
     * @throws XmlParserException
     *             thrown if there is a problem retrieving a builder
     */
    public Document newDocument() throws XmlParserException;

    /**
     * Convience method for parsing an XML file using a pooled builder.
     *
     * @param input
     *            XML to parse
     *
     * @return parsed document
     *
     * @throws XmlParserException
     *             thrown if there is a problem retrieving a builder, the input stream can not be read, or the XML was
     *             invalid
     */
    public Document parse(InputStream input) throws XmlParserException;

    /**
     * Convience method for parsing an XML file using a pooled builder.
     *
     * @param input
     *            XML to parse
     *
     * @return parsed document
     *
     * @throws XmlParserException
     *             thrown if there is a problem retrieving a builder, the input stream can not be read, or the XML was
     *             invalid
     */
    public Document parse(Reader input) throws XmlParserException;

    /**
     * Gets the schema builders use to validate.
     *
     * @return the schema builders use to validate
     */
    public Schema getSchema();

    /**
     * Sets the schema builders use to validate.
     *
     * @param newSchema
     *            the schema builders use to validate
     */
    public void setSchema(Schema newSchema);

}
